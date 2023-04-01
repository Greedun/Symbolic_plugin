import importlib

# 모듈이 없을 경우 자동으로 설치후 import
def import_or_install(package):
    try:
        importlib.import_module(package)
    except ImportError:
        import subprocess
        subprocess.check_call(["pip3", "install", package])
    finally:
        globals()[package] = importlib.import_module(package)
    
    import capstone

# cs_assembly -> gef_to_cs_arch
def gef_to_cs_arch() -> Tuple[str, str, str]:
    if gef.arch.arch == "ARM":
        if isinstance(gef.arch, ARM):
            if gef.arch.is_thumb():
                return "CS_ARCH_ARM", "CS_MODE_THUMB", f"CS_MODE_{repr(gef.arch.endianness).upper()}"
            return "CS_ARCH_ARM", "CS_MODE_ARM", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    if gef.arch.arch == "ARM64":
        return "CS_ARCH_ARM64", "0", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    if gef.arch.arch == "X86":
        if gef.arch.mode == "32":
            return "CS_ARCH_X86", "CS_MODE_32", f"CS_MODE_{repr(gef.arch.endianness).upper()}"
        if gef.arch.mode == "64":
            return "CS_ARCH_X86", "CS_MODE_64", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    if gef.arch.arch == "PPC":
        if gef.arch.mode == "PPC32":
            return "CS_ARCH_PPC", "CS_MODE_PPC32", f"CS_MODE_{repr(gef.arch.endianness).upper()}"
        if gef.arch.mode == "PPC64":
            return "CS_ARCH_PPC", "CS_MODE_PPC64", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    if gef.arch.arch == "MIPS":
        if gef.arch.mode == "MIPS32":
            return "CS_ARCH_MIPS", "CS_MODE_MIPS32", f"CS_MODE_{repr(gef.arch.endianness).upper()}"
        if gef.arch.mode == "MIPS64":
            return "CS_ARCH_MIPS32", "CS_MODE_MIPS64", f"CS_MODE_{repr(gef.arch.endianness).upper()}"

    raise ValueError

def cs_disassemble(location: int, nb_insn: int, **kwargs: Any) -> Generator[Instruction, None, None]:
    #print(f"Valr : {hex(location)} , {nb_insn} , {kwargs}")
    """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before
    `addr` using the Capstone-Engine disassembler, if available.
    Return an iterator of Instruction objects."""

    # capstone을 gef의 Instruction으로 변환
    def cs_insn_to_gef_insn(cs_insn: capstone.CsInsn) -> Instruction:
        sym_info = gdb_get_location_from_symbol(cs_insn.address)
        loc = "<{}+{}>".format(*sym_info) if sym_info else ""
        ops = [] + cs_insn.op_str.split(", ")
        return Instruction(cs_insn.address, loc, cs_insn.mnemonic, ops, cs_insn.bytes)

    arch_s, mode_s, endian_s = gef_to_cs_arch()
    # getattr : type을 넣었을때 해당되는 int값 반환
    cs_arch: int = getattr(capstone, arch_s)
    cs_mode: int = getattr(capstone, mode_s)
    cs_endian: int = getattr(capstone, endian_s)

    # location : 현재위치, page_start : page시작점, offset : location은 시작점에서 얼마나 떨어졌는가
    cs = capstone.Cs(cs_arch, cs_mode | cs_endian) # 클래스 반환?
    cs.detail = True
    page_start = align_address_to_page(location)
    offset = location - page_start

    skip = int(kwargs.get("skip", 0)) # skip값 얻기
    nb_prev = int(kwargs.get("nb_prev", 0)) # nb_prev값 얻기
    pc = gef.arch.pc # $pc값 얻기

    if nb_prev > 0:
        location = gdb_get_nth_previous_instruction_address(pc, nb_prev) or -1
        if location < 0:
            err(f"failed to read previous instruction")
            return
        nb_insn += nb_prev
    # code : location부터 바이너리 읽어오는 값 저장
    code = kwargs.get("code", gef.memory.read(
        location, gef.session.pagesize - offset - 1))

    # code에 
    for insn in cs.disasm(code, location):
        if skip:
            skip -= 1
            continue
        nb_insn -= 1
        yield cs_insn_to_gef_insn(insn) # yield는 무엇인가?
        if nb_insn == 0:
            break
    return

# insn내부 값 확인 용도
def confirm_inst(insn):
    print(f"Address : {hex(insn.address)}")
    print(f"is_valid : {insn.is_valid}") # ?
    print(f"Location : {insn.location}")
    print(f"mnemonic : {insn.mnemonic}")
    print(f"opcode : {insn.opcodes}")
    print(f"operand : {insn.operands}")
    print(f"size : {insn.size}")
    print()


class Taint_Reg(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "TaintReg"
    _syntax_  = f"{_cmdline_}"
    
    
    @only_if_gdb_running         # not required, ensures that the debug session is started
    @parse_arguments({("location"): "$pc"}, {("--show-opcodes", "-s"): True, "--length": 0}) # kwarg사용시 필요
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        import_or_install("capstone")
        
        args = kwargs["arguments"]
        length = args.length or gef.config["context.nb_lines_code"] # or : bit연산자 , config : 6
        location = parse_address(args.location) #int값 반환
        
        # 주소 여부 확인
        if not location:
            info(f"Can't find address for {args.location}")
            return
        
        insns = [] # 의문의 클래스로 들어감
        opcodes_len = 0
        for insn in cs_disassemble(location, length, skip=length * self.repeat_count, **kwargs):
            insns.append(insn)
            opcodes_len = max(opcodes_len, len(insn.opcodes)) # ?
        # confirm_inst(insns[0])
        
        # let's say we want to print some info about the architecture of the current binary
        print(f"gef.arch={gef.arch}")
        # or showing the current $pc
        print(f"gef.arch.pc={gef.arch.pc:#x}")
        return

# 명령어 : clear용도
class clear(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "clear"
    #_syntax_  = f"{_cmdline_}"
    _syntax_ = f"{_cmdline_} [-h] [--show-opcodes] [--length LENGTH] [LOCATION]"

    @only_if_gdb_running         # not required, ensures that the debug session is started
    def do_invoke(self, argv):
        clear_screen()
        return

register_external_command(Taint_Reg())
register_external_command(clear())

'''
[알고리즘 구상도]
elf 분석 라이브러리 : pylibelf(X)
=> gefaddrspace존재

----
1. elf구조를 통한 주소, 어셈블리어 추출
=> 사전 작업 + 내부 기능으로 해결
=> capstone.py 참고

2. 오염 분석할 주소 및 레지스터 지정

3. (ni, si중) 실행되면서 만약 레지스터가 오염된다면 alert
=> 오염되는 기준을 정할 레지스터
=> MOV, CALL, LEA, CMP, TEST, 산술 연산자, RET, MOV, PUSH, POP, JUMP
<si는 무시하되 만약 매개변수로 오염변수가 들어간다면 반환값이 오염된다고 가정>
(1) 매 실행마다 적용되는 방법을 찾기
=> 만약 못찾는다면 비동기로 뒤에서 계속 실행하여 주소(pc)가 달라졌을때 반영하게 된다.
(2) (1)이 될 떄 미리 지정한 영향받는 어셈블리어가 들어있을 경우
레지스터 오염 추적 여부를 확인하고 오염됬을시 확인한다.
=> (?) 오염 추적를 어떻게 따라갈껀지 구상해야함


(+) 설정한 값 초기화하는 기능
(+) 현재 진행중인 오염 상황을 출력하는 기능
'''
