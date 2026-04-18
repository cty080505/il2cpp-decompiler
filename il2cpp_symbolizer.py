#!/usr/bin/env python3
"""
IL2CPP Symbolizer Tool
利用 global-metadata.dat 对 GameAssembly.dll 进行符号化

该工具解析 Unity IL2CPP 的 global-metadata.dat 文件，
提取类型和方法信息，并生成可用于符号化的输出文件。
"""

import argparse
import struct
import os
import sys
import mmap
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, BinaryIO
from enum import IntEnum


class Il2CppTypeEnum(IntEnum):
    """IL2CPP 类型枚举"""
    IL2CPP_TYPE_END = 0x00
    IL2CPP_TYPE_VOID = 0x01
    IL2CPP_TYPE_BOOLEAN = 0x02
    IL2CPP_TYPE_CHAR = 0x03
    IL2CPP_TYPE_I1 = 0x04
    IL2CPP_TYPE_U1 = 0x05
    IL2CPP_TYPE_I2 = 0x06
    IL2CPP_TYPE_U2 = 0x07
    IL2CPP_TYPE_I4 = 0x08
    IL2CPP_TYPE_U4 = 0x09
    IL2CPP_TYPE_I8 = 0x0a
    IL2CPP_TYPE_U8 = 0x0b
    IL2CPP_TYPE_R4 = 0x0c
    IL2CPP_TYPE_R8 = 0x0d
    IL2CPP_TYPE_STRING = 0x0e
    IL2CPP_TYPE_PTR = 0x0f
    IL2CPP_TYPE_BYREF = 0x10
    IL2CPP_TYPE_VALUETYPE = 0x11
    IL2CPP_TYPE_CLASS = 0x12
    IL2CPP_TYPE_VAR = 0x13
    IL2CPP_TYPE_ARRAY = 0x14
    IL2CPP_TYPE_GENERICINST = 0x15
    IL2CPP_TYPE_TYPEDBYREF = 0x16
    IL2CPP_TYPE_I = 0x18
    IL2CPP_TYPE_U = 0x19
    IL2CPP_TYPE_FNPTR = 0x1b
    IL2CPP_TYPE_OBJECT = 0x1c
    IL2CPP_TYPE_SZARRAY = 0x1d
    IL2CPP_TYPE_MVAR = 0x1e
    IL2CPP_TYPE_CMOD_REQD = 0x1f
    IL2CPP_TYPE_CMOD_OPT = 0x20
    IL2CPP_TYPE_INTERNAL = 0x21
    IL2CPP_TYPE_MODIFIER = 0x40
    IL2CPP_TYPE_SENTINEL = 0x41
    IL2CPP_TYPE_PINNED = 0x45
    IL2CPP_TYPE_ENUM = 0x55
    IL2CPP_TYPE_IL2CPP_TYPE_INDEX = 0xff


@dataclass
class Il2CppString:
    """IL2CPP 字符串结构"""
    length: int
    value: str


@dataclass
class Il2CppTypeDefinition:
    """IL2CPP 类型定义"""
    name_index: int
    namespace_index: int
    byval_type_index: int
    byref_type_index: int
    declaring_type_index: int
    parent_index: int
    element_type_index: int
    assembly_index: int
    flags: int
    type_token: int
    rank: int
    interface_count: int
    interfaces_offset: int
    vtable_count: int
    vtable_offset: int
    interface_offsets_count: int
    interface_offsets_offset: int
    rgctx_start_index: int
    rgctx_count: int
    generic_container_index: int
    custom_attribute_index: int
    declared_size: int
    actual_size: int
    bitfield: int
    
    # 解析后的值
    name: str = ""
    namespace: str = ""
    full_name: str = ""


@dataclass
class Il2CppMethodDefinition:
    """IL2CPP 方法定义"""
    name_index: int
    declaring_type: int
    return_type: int
    token: int
    parameter_start: int
    parameter_count: int
    generic_container_index: int
    flags: int
    iflags: int
    slot: int
    rgctx_start_index: int
    
    # 解析后的值
    name: str = ""
    return_type_name: str = ""
    parameters: List[str] = field(default_factory=list)
    signature: str = ""
    full_name: str = ""
    
    # 地址信息（从 symbol 文件获取）
    address: int = 0
    size: int = 0


@dataclass
class Il2CppParameterDefinition:
    """IL2CPP 参数定义"""
    name_index: int
    token: int
    type_index: int
    
    # 解析后的值
    name: str = ""
    type_name: str = ""


@dataclass
class MethodSymbol:
    """方法符号信息"""
    name: str
    address: int
    size: int
    signature: str
    full_name: str


class MetadataReader:
    """global-metadata.dat 读取器（使用内存映射避免大文件内存问题）"""
    
    # 元数据头魔术数字
    METADATA_MAGIC = 0xFAB11BAF
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data: bytes = b''
        self.mmapped_file = None
        self.mmapped_data = None
        self.header: dict = {}
        self.strings: Dict[int, str] = {}
        self.types: List[Il2CppTypeDefinition] = []
        self.methods: List[Il2CppMethodDefinition] = []
        self.parameters: List[Il2CppParameterDefinition] = []
        
    def read(self) -> bool:
        """读取元数据文件（使用内存映射）"""
        try:
            file_size = os.path.getsize(self.filepath)
            
            # 对于小文件（< 100MB），直接读取到内存
            if file_size < 100 * 1024 * 1024:
                with open(self.filepath, 'rb') as f:
                    self.data = f.read()
            else:
                # 对于大文件，使用内存映射
                self.mmapped_file = open(self.filepath, 'rb')
                self.mmapped_data = mmap.mmap(self.mmapped_file.fileno(), 0, access=mmap.ACCESS_READ)
                self.data = self.mmapped_data
            
            if len(self.data) < 64:
                print(f"错误：文件太小，不是有效的元数据文件")
                return False
                
            return self._parse_header()
        except Exception as e:
            print(f"错误：无法读取文件 - {e}")
            return False
    
    def close(self):
        """关闭文件和内存映射"""
        if self.mmapped_data is not None:
            self.mmapped_data.close()
        if self.mmapped_file is not None:
            self.mmapped_file.close()
    
    def _parse_header(self) -> bool:
        """解析元数据头"""
        # 读取魔术数字
        magic = struct.unpack_from('<I', self.data, 0)[0]
        if magic != self.METADATA_MAGIC:
            print(f"错误: 无效的魔术数字 0x{magic:08X}，期望 0x{self.METADATA_MAGIC:08X}")
            return False
        
        version = struct.unpack_from('<I', self.data, 4)[0]
        string_offset = struct.unpack_from('<I', self.data, 8)[0]
        string_size = struct.unpack_from('<I', self.data, 12)[0]
        events_offset = struct.unpack_from('<I', self.data, 16)[0]
        events_size = struct.unpack_from('<I', self.data, 20)[0]
        properties_offset = struct.unpack_from('<I', self.data, 24)[0]
        properties_size = struct.unpack_from('<I', self.data, 28)[0]
        methods_offset = struct.unpack_from('<I', self.data, 32)[0]
        methods_size = struct.unpack_from('<I', self.data, 36)[0]
        parameter_defaults_offset = struct.unpack_from('<I', self.data, 40)[0]
        parameter_defaults_size = struct.unpack_from('<I', self.data, 44)[0]
        field_marshals_offset = struct.unpack_from('<I', self.data, 48)[0]
        field_marshals_size = struct.unpack_from('<I', self.data, 52)[0]
        decl_security_offset = struct.unpack_from('<I', self.data, 56)[0]
        decl_security_size = struct.unpack_from('<I', self.data, 60)[0]
        
        self.header = {
            'version': version,
            'string_offset': string_offset,
            'string_size': string_size,
            'events_offset': events_offset,
            'events_size': events_size,
            'properties_offset': properties_offset,
            'properties_size': properties_size,
            'methods_offset': methods_offset,
            'methods_size': methods_size,
            'parameter_defaults_offset': parameter_defaults_offset,
            'parameter_defaults_size': parameter_defaults_size,
            'field_marshals_offset': field_marshals_offset,
            'field_marshals_size': field_marshals_size,
            'decl_security_offset': decl_security_offset,
            'decl_security_size': decl_security_size,
        }
        
        print(f"元数据版本: {version}")
        print(f"字符串表偏移: 0x{string_offset:X}, 大小: {string_size}")
        print(f"方法表偏移: 0x{methods_offset:X}, 大小: {methods_size}")
        
        return True
    
    def parse_strings(self) -> None:
        """解析字符串表"""
        offset = self.header['string_offset']
        size = self.header['string_size']
        
        end_offset = offset + size
        current = offset
        
        while current < end_offset and current < len(self.data):
            # 读取字符串长度（以 null 结尾）
            start = current
            while current < len(self.data) and self.data[current] != 0:
                current += 1
            
            if current < len(self.data):
                try:
                    string_value = self.data[start:current].decode('utf-8')
                    self.strings[start - offset] = string_value
                except UnicodeDecodeError:
                    try:
                        string_value = self.data[start:current].decode('latin-1')
                        self.strings[start - offset] = string_value
                    except:
                        self.strings[start - offset] = "<invalid>"
                current += 1  # 跳过 null 终止符
            else:
                break
        
        print(f"已解析 {len(self.strings)} 个字符串")
    
    def get_string(self, index: int) -> str:
        """根据索引获取字符串"""
        if index in self.strings:
            return self.strings[index]
        return f"<string_{index}>"
    
    def parse_types(self, types_offset: int, types_count: int) -> None:
        """解析类型定义"""
        # IL2CPP 类型定义结构大小（不同版本可能不同）
        # 这里使用较新的结构大小
        type_size = 68  # 对于较新版本的 Unity
        
        for i in range(types_count):
            offset = types_offset + (i * type_size)
            if offset + type_size > len(self.data):
                break
            
            try:
                tdef = Il2CppTypeDefinition(
                    name_index=struct.unpack_from('<I', self.data, offset)[0],
                    namespace_index=struct.unpack_from('<I', self.data, offset + 4)[0],
                    byval_type_index=struct.unpack_from('<I', self.data, offset + 8)[0],
                    byref_type_index=struct.unpack_from('<I', self.data, offset + 12)[0],
                    declaring_type_index=struct.unpack_from('<I', self.data, offset + 16)[0],
                    parent_index=struct.unpack_from('<I', self.data, offset + 20)[0],
                    element_type_index=struct.unpack_from('<I', self.data, offset + 24)[0],
                    assembly_index=struct.unpack_from('<I', self.data, offset + 28)[0],
                    flags=struct.unpack_from('<I', self.data, offset + 32)[0],
                    type_token=struct.unpack_from('<I', self.data, offset + 36)[0],
                    rank=struct.unpack_from('<I', self.data, offset + 40)[0],
                    interface_count=struct.unpack_from('<H', self.data, offset + 44)[0],
                    interfaces_offset=struct.unpack_from('<H', self.data, offset + 46)[0],
                    vtable_count=struct.unpack_from('<H', self.data, offset + 48)[0],
                    vtable_offset=struct.unpack_from('<H', self.data, offset + 50)[0],
                    interface_offsets_count=struct.unpack_from('<H', self.data, offset + 52)[0],
                    interface_offsets_offset=struct.unpack_from('<H', self.data, offset + 54)[0],
                    rgctx_start_index=struct.unpack_from('<I', self.data, offset + 56)[0],
                    rgctx_count=struct.unpack_from('<I', self.data, offset + 60)[0],
                    generic_container_index=struct.unpack_from('<I', self.data, offset + 64)[0],
                    custom_attribute_index=struct.unpack_from('<I', self.data, offset + 68)[0] if type_size > 68 else -1,
                    declared_size=struct.unpack_from('<I', self.data, offset + 72)[0] if type_size > 72 else 0,
                    actual_size=struct.unpack_from('<I', self.data, offset + 76)[0] if type_size > 76 else 0,
                    bitfield=struct.unpack_from('<I', self.data, offset + 80)[0] if type_size > 80 else 0,
                )
                
                tdef.name = self.get_string(tdef.name_index)
                tdef.namespace = self.get_string(tdef.namespace_index)
                
                if tdef.namespace:
                    tdef.full_name = f"{tdef.namespace}.{tdef.name}"
                else:
                    tdef.full_name = tdef.name
                
                self.types.append(tdef)
            except Exception as e:
                print(f"解析类型 {i} 时出错: {e}")
                continue
        
        print(f"已解析 {len(self.types)} 个类型")
    
    def parse_methods(self, methods_offset: int, methods_count: int) -> None:
        """解析方法定义"""
        # IL2CPP 方法定义结构大小
        method_size = 44  # 对于较新版本的 Unity
        
        for i in range(methods_count):
            offset = methods_offset + (i * method_size)
            if offset + method_size > len(self.data):
                break
            
            try:
                mdef = Il2CppMethodDefinition(
                    name_index=struct.unpack_from('<I', self.data, offset)[0],
                    declaring_type=struct.unpack_from('<I', self.data, offset + 4)[0],
                    return_type=struct.unpack_from('<I', self.data, offset + 8)[0],
                    token=struct.unpack_from('<I', self.data, offset + 12)[0],
                    parameter_start=struct.unpack_from('<I', self.data, offset + 16)[0],
                    parameter_count=struct.unpack_from('<I', self.data, offset + 20)[0],
                    generic_container_index=struct.unpack_from('<I', self.data, offset + 24)[0],
                    flags=struct.unpack_from('<I', self.data, offset + 28)[0],
                    iflags=struct.unpack_from('<I', self.data, offset + 32)[0],
                    slot=struct.unpack_from('<H', self.data, offset + 36)[0],
                    rgctx_start_index=struct.unpack_from('<H', self.data, offset + 38)[0],
                )
                
                mdef.name = self.get_string(mdef.name_index)
                self.methods.append(mdef)
            except Exception as e:
                print(f"解析方法 {i} 时出错: {e}")
                continue
        
        print(f"已解析 {len(self.methods)} 个方法")
    
    def parse_parameters(self, params_offset: int, params_count: int) -> None:
        """解析参数定义"""
        param_size = 12
        
        for i in range(params_count):
            offset = params_offset + (i * param_size)
            if offset + param_size > len(self.data):
                break
            
            try:
                pdef = Il2CppParameterDefinition(
                    name_index=struct.unpack_from('<I', self.data, offset)[0],
                    token=struct.unpack_from('<I', self.data, offset + 4)[0],
                    type_index=struct.unpack_from('<I', self.data, offset + 8)[0],
                )
                
                pdef.name = self.get_string(pdef.name_index)
                self.parameters.append(pdef)
            except Exception as e:
                print(f"解析参数 {i} 时出错: {e}")
                continue
        
        print(f"已解析 {len(self.parameters)} 个参数")
    
    def parse_all(self, types_offset: int = 0, types_count: int = 0) -> None:
        """解析所有元数据"""
        self.parse_strings()
        
        # 使用方法表中的信息
        methods_offset = self.header['methods_offset']
        methods_size = self.header['methods_size']
        if methods_size > 0:
            methods_count = methods_size // 44
            self.parse_methods(methods_offset, methods_count)
        
        params_offset = self.header.get('parameter_defaults_offset', 0)
        params_size = self.header.get('parameter_defaults_size', 0)
        if params_size > 0 and params_offset > 0:
            params_count = params_size // 12
            self.parse_parameters(params_offset, params_count)


class SymbolFileParser:
    """符号文件解析器（如 .sym 或 .map 文件）"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.symbols: Dict[str, MethodSymbol] = {}
        
    def parse(self) -> bool:
        """解析符号文件"""
        if not os.path.exists(self.filepath):
            print(f"警告: 符号文件不存在 - {self.filepath}")
            return False
        
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            address = int(parts[0], 16)
                            size = int(parts[1], 16) if len(parts) > 2 else 0
                            name = parts[2] if len(parts) > 2 else parts[-1]
                            
                            symbol = MethodSymbol(
                                name=name,
                                address=address,
                                size=size,
                                signature="",
                                full_name=""
                            )
                            self.symbols[name] = symbol
                        except ValueError:
                            continue
            
            print(f"已解析 {len(self.symbols)} 个符号")
            return True
        except Exception as e:
            print(f"错误: 无法解析符号文件 - {e}")
            return False


class IL2CPPSymbolizer:
    """IL2CPP 符号化工具主类"""
    
    def __init__(self, metadata_path: str, dll_path: str = "", symbol_path: str = ""):
        self.metadata_path = metadata_path
        self.dll_path = dll_path
        self.symbol_path = symbol_path
        self.metadata_reader = MetadataReader(metadata_path)
        self.symbol_parser = SymbolFileParser(symbol_path) if symbol_path else None
        self.method_addresses: Dict[int, Tuple[int, int]] = {}  # token -> (address, size)
        
    def load_metadata(self) -> bool:
        """加载元数据"""
        if not self.metadata_reader.read():
            return False
        
        # 解析字符串、方法和参数
        self.metadata_reader.parse_strings()
        
        methods_offset = self.metadata_reader.header['methods_offset']
        methods_size = self.metadata_reader.header['methods_size']
        if methods_size > 0:
            methods_count = methods_size // 44
            self.metadata_reader.parse_methods(methods_offset, methods_count)
        
        params_offset = self.metadata_reader.header.get('parameter_defaults_offset', 0)
        params_size = self.metadata_reader.header.get('parameter_defaults_size', 0)
        if params_size > 0 and params_offset > 0:
            params_count = params_size // 12
            self.metadata_reader.parse_parameters(params_offset, params_count)
        
        return True
    
    def load_symbols(self) -> bool:
        """加载符号文件"""
        if self.symbol_parser:
            return self.symbol_parser.parse()
        return False
    
    def set_method_address(self, token: int, address: int, size: int) -> None:
        """设置方法地址"""
        self.method_addresses[token] = (address, size)
    
    def _get_type_name(self, type_index: int) -> str:
        """根据类型索引获取类型名称"""
        if 0 <= type_index < len(self.metadata_reader.types):
            return self.metadata_reader.types[type_index].full_name
        return f"<type_{type_index}>"
    
    def _build_method_signature(self, method: Il2CppMethodDefinition) -> str:
        """构建方法签名"""
        # 获取返回类型
        return_type = self._get_type_name(method.return_type)
        
        # 获取参数列表
        params = []
        param_start = method.parameter_start
        param_count = method.parameter_count
        
        for i in range(param_count):
            param_index = param_start + i
            if 0 <= param_index < len(self.metadata_reader.parameters):
                param = self.metadata_reader.parameters[param_index]
                param_type = self._get_type_name(param.type_index)
                params.append(f"{param_type} {param.name}")
            else:
                params.append(f"<param_{i}>")
        
        return f"{return_type} ({', '.join(params)})"
    
    def symbolize_methods_generator(self):
        """符号化所有方法（生成器版本，流式处理避免内存溢出）"""
        
        for method in self.metadata_reader.methods:
            # 获取方法所属的类型
            type_index = method.declaring_type
            type_name = ""
            if 0 <= type_index < len(self.metadata_reader.types):
                type_name = self.metadata_reader.types[type_index].full_name
            
            # 构建完整方法名
            method.full_name = f"{type_name}::{method.name}" if type_name else method.name
            method.signature = self._build_method_signature(method)
            
            # 获取地址信息
            address = 0
            size = 0
            if method.token in self.method_addresses:
                address, size = self.method_addresses[method.token]
            elif self.symbol_parser and method.name in self.symbol_parser.symbols:
                sym = self.symbol_parser.symbols[method.name]
                address = sym.address
                size = sym.size
            
            symbol = MethodSymbol(
                name=method.name,
                address=address,
                size=size,
                signature=method.signature,
                full_name=method.full_name
            )
            yield symbol
    
    def symbolize_methods(self) -> List[MethodSymbol]:
        """符号化所有方法（返回列表版本，兼容旧代码但可能消耗较多内存）"""
        return list(self.symbolize_methods_generator())
    
    def generate_symbol_file(self, output_path: str, symbols=None) -> bool:
        """生成符号文件（支持流式写入）"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# IL2CPP Symbol File\n")
                f.write("# Format: Address Size Name Signature FullName\n")
                f.write("#\n")
                
                # 如果是生成器，则流式处理；如果是列表，则排序后写入
                if hasattr(symbols, '__iter__') and not isinstance(symbols, list):
                    # 流式处理生成器
                    count = 0
                    for sym in symbols:
                        if sym.address > 0:
                            f.write(f"0x{sym.address:016X} {sym.size:8d} {sym.full_name} \"{sym.signature}\"\n")
                            count += 1
                    print(f"符号文件已生成：{output_path}")
                    print(f"共写入 {count} 个符号")
                else:
                    # 列表模式，可以排序
                    sorted_symbols = sorted(symbols, key=lambda s: s.address if s.address > 0 else float('inf'))
                    
                    for sym in sorted_symbols:
                        if sym.address > 0:
                            f.write(f"0x{sym.address:016X} {sym.size:8d} {sym.full_name} \"{sym.signature}\"\n")
                    
                    print(f"符号文件已生成：{output_path}")
                    print(f"共写入 {len(symbols)} 个符号")
            return True
        except Exception as e:
            print(f"错误：无法生成符号文件 - {e}")
            return False
    
    def generate_symbol_file_streaming(self, output_path: str) -> bool:
        """生成符号文件（流式版本，边生成边保存，避免内存溢出）"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# IL2CPP Symbol File\n")
                f.write("# Format: Address Size Name Signature FullName\n")
                f.write("#\n")
                
                count = 0
                for sym in self.symbolize_methods_generator():
                    if sym.address > 0:
                        f.write(f"0x{sym.address:016X} {sym.size:8d} {sym.full_name} \"{sym.signature}\"\n")
                        count += 1
                
                print(f"符号文件已生成：{output_path}")
                print(f"共写入 {count} 个符号")
            return True
        except Exception as e:
            print(f"错误：无法生成符号文件 - {e}")
            return False
    def generate_ida_script(self, output_path: str, symbols=None) -> bool:
        """生成 IDA Python 脚本（支持流式写入）"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# IDA Python Script for IL2CPP Symbolization\n")
                f.write("# Generated by IL2CPP Symbolizer\n")
                f.write("\n")
                f.write("import idaapi\n")
                f.write("import idc\n")
                f.write("\n")
                f.write("def apply_symbols():\n")
                f.write("    symbols = [\n")
                
                # 如果是生成器，则流式处理；如果是列表，则直接迭代
                symbol_iter = symbols if symbols is not None else self.symbolize_methods_generator()
                for sym in symbol_iter:
                    if sym.address > 0:
                        f.write(f"        (0x{sym.address:X}, \"{sym.full_name}\"),\n")
                
                f.write("    ]\n")
                f.write("\n")
                f.write("    for address, name in symbols:\n")
                f.write("        if idaapi.get_func(address):\n")
                f.write("            idc.set_name(address, name, idaapi.SN_CHECK)\n")
                f.write("            print(f\"Applied symbol: {name} at 0x{address:X}\")\n")
                f.write("\n")
                f.write("if __name__ == \"__main__\":\n")
                f.write("    apply_symbols()\n")
            
            print(f"IDA 脚本已生成: {output_path}")
            return True
        except Exception as e:
            print(f"错误: 无法生成 IDA 脚本 - {e}")
            return False
    
    def generate_ghidra_script(self, output_path: str, symbols=None) -> bool:
        """生成 Ghidra 脚本（支持流式写入）"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("// Ghidra Script for IL2CPP Symbolization\n")
                f.write("// Generated by IL2CPP Symbolizer\n")
                f.write("\n")
                f.write("#lang python\n")
                f.write("\n")
                f.write("from ghidra.program.model.symbol import SourceType\n")
                f.write("\n")
                f.write("def apply_symbols():\n")
                f.write("    symbols = [\n")
                
                # 如果是生成器，则流式处理；如果是列表，则直接迭代
                symbol_iter = symbols if symbols is not None else self.symbolize_methods_generator()
                for sym in symbol_iter:
                    if sym.address > 0:
                        f.write(f"        (0x{sym.address:X}, \"{sym.full_name}\"),\n")
                
                f.write("    ]\n")
                f.write("\n")
                f.write("    for address, name in symbols:\n")
                f.write("        addr = toAddr(address)\n")
                f.write("        func = getFunctionAt(addr)\n")
                f.write("        if func:\n")
                f.write("            func.setName(name, SourceType.USER_DEFINED)\n")
                f.write("            print(f\"Applied symbol: {name} at 0x{address:X}\")\n")
                f.write("\n")
                f.write("apply_symbols()\n")
            
            print(f"Ghidra 脚本已生成: {output_path}")
            return True
        except Exception as e:
            print(f"错误: 无法生成 Ghidra 脚本 - {e}")
            return False
    
    def dump_methods(self, output_path: str, symbols: List[MethodSymbol]) -> bool:
        """导出方法列表"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# IL2CPP Methods\n")
                f.write("# Format: Token Address Size FullName Signature\n")
                f.write("#\n")
                
                for i, method in enumerate(self.metadata_reader.methods):
                    sym = symbols[i] if i < len(symbols) else None
                    token = method.token
                    address = sym.address if sym else 0
                    size = sym.size if sym else 0
                    full_name = sym.full_name if sym else method.name
                    signature = sym.signature if sym else ""
                    
                    f.write(f"0x{token:08X} 0x{address:016X} {size:8d} {full_name} \"{signature}\"\n")
            
            print(f"方法列表已导出: {output_path}")
            return True
        except Exception as e:
            print(f"错误: 无法导出方法列表 - {e}")
            return False



    def dump_methods_streaming(self, output_path: str) -> bool:
        """导出方法列表（流式版本）"""
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("# IL2CPP Methods\n")
                f.write("# Format: Token Address Size FullName Signature\n")
                f.write("#\n")

                for method in self.metadata_reader.methods:
                    # 获取方法所属的类型
                    type_index = method.declaring_type
                    type_name = ""
                    if 0 <= type_index < len(self.metadata_reader.types):
                        type_name = self.metadata_reader.types[type_index].full_name
                    
                    full_name = f"{type_name}::{method.name}" if type_name else method.name
                    signature = self._build_method_signature(method)
                    
                    # 获取地址信息
                    address = 0
                    size = 0
                    if method.token in self.method_addresses:
                        address, size = self.method_addresses[method.token]
                    elif self.symbol_parser and method.name in self.symbol_parser.symbols:
                        sym = self.symbol_parser.symbols[method.name]
                        address = sym.address
                        size = sym.size

                    token = method.token
                    f.write(f"0x{token:08X} 0x{address:016X} {size:8d} {full_name} \"{signature}\"\n")

            print(f"方法列表已导出：{output_path}")
            return True
        except Exception as e:
            print(f"错误：无法导出方法列表 - {e}")
            return False

def main():
    parser = argparse.ArgumentParser(
        description='IL2CPP Symbolizer - 利用 global-metadata.dat 对 GameAssembly.dll 进行符号化',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 仅解析元数据并导出方法列表
  python il2cpp_symbolizer.py -m global-metadata.dat --dump methods.txt
  
  # 使用符号文件进行符号化
  python il2cpp_symbolizer.py -m global-metadata.dat -s symbols.txt -o symbols_out.txt
  
  # 生成 IDA 脚本
  python il2cpp_symbolizer.py -m global-metadata.dat -s symbols.txt --ida script.py
  
  # 生成 Ghidra 脚本
  python il2cpp_symbolizer.py -m global-metadata.dat -s symbols.txt --ghidra script.py
        """
    )
    
    parser.add_argument('-m', '--metadata', required=True, help='global-metadata.dat 文件路径')
    parser.add_argument('-d', '--dll', help='GameAssembly.dll 文件路径（可选）')
    parser.add_argument('-s', '--symbols', help='符号文件路径（.sym/.map 格式）')
    parser.add_argument('-o', '--output', help='输出符号文件路径')
    parser.add_argument('--streaming', action='store_true', help='使用流式模式生成符号文件（避免内存溢出）')
    parser.add_argument('--ida', help='生成 IDA Python 脚本')
    parser.add_argument('--ghidra', help='生成 Ghidra 脚本')
    parser.add_argument('--dump', help='导出方法列表到文件')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("IL2CPP Symbolizer")
    print("=" * 60)
    
    # 创建符号化工具实例
    symbolizer = IL2CPPSymbolizer(
        metadata_path=args.metadata,
        dll_path=args.dll or "",
        symbol_path=args.symbols or ""
    )
    
    # 加载元数据
    print(f"\n加载元数据文件: {args.metadata}")
    if not symbolizer.load_metadata():
        print("错误: 无法加载元数据文件")
        sys.exit(1)
    
    # 加载符号文件（如果提供）
    if args.symbols:
        print(f"\n加载符号文件: {args.symbols}")
        symbolizer.load_symbols()
    
    # 符号化方法
    print("\n符号化处理中...")

    # 输出结果
    if args.output:
        print(f"\n生成符号文件：{args.output}")
        if args.streaming:
            # 流式模式，避免内存溢出
            symbolizer.generate_symbol_file_streaming(args.output)
            symbols = None
        else:
            # 传统模式，加载所有符号到内存
            symbols = symbolizer.symbolize_methods()
            symbolizer.generate_symbol_file(args.output, symbols)
    else:
        # 如果没有输出文件，但仍需要符号列表（用于 IDA/Ghidra 脚本）
        if args.streaming:
            symbols = None  # 流式模式下不保留列表
        else:
            symbols = symbolizer.symbolize_methods()
    
    if args.ida:
        print(f"\n生成 IDA 脚本：{args.ida}")
        if args.streaming:
            # 流式模式：直接传递生成器
            symbolizer.generate_ida_script(args.ida, symbolizer.symbolize_methods_generator())
        else:
            symbolizer.generate_ida_script(args.ida, symbols)

    if args.ghidra:
        print(f"\n生成 Ghidra 脚本：{args.ghidra}")
        if args.streaming:
            # 流式模式：直接传递生成器
            symbolizer.generate_ghidra_script(args.ghidra, symbolizer.symbolize_methods_generator())
        else:
            symbolizer.generate_ghidra_script(args.ghidra, symbols)

    if args.dump:
        print(f"\n导出方法列表：{args.dump}")
        if args.streaming:
            # 流式模式：重新生成一次用于 dump
            symbolizer.dump_methods_streaming(args.dump)
        else:
            symbolizer.dump_methods(args.dump, symbols)
    # 如果没有指定输出，显示统计信息
    if not any([args.output, args.ida, args.ghidra, args.dump]):
        print(f"\n统计信息:")
        print(f"  类型数量: {len(symbolizer.metadata_reader.types)}")
        print(f"  方法数量: {len(symbolizer.metadata_reader.methods)}")
        print(f"  参数数量: {len(symbolizer.metadata_reader.parameters)}")
        
        # 显示前 10 个方法
        if symbols:
            print(f"\n前 10 个方法:")
            for i, sym in enumerate(symbols[:10]):
                addr_str = f"0x{sym.address:X}" if sym.address > 0 else "N/A"
                print(f"  [{i}] {sym.full_name} @ {addr_str}")
    
    # 关闭资源
    symbolizer.metadata_reader.close()
    print("\n" + "=" * 60)
    print("完成!")
    print("=" * 60)


if __name__ == '__main__':
    main()
