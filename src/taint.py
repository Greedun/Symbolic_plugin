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
# 아키텍처에 따른 모드 값 반환
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
    _syntax_  = f"{_cmdline_} [location] [--set] [--monitor] [--print] [--clear]"
    
    # location 지정 없을때 $pc에 있는 레지스터 / location 지정 있을때 location에 있는 레지스터
    @only_if_gdb_running         # not required, ensures that the debug session is started
    @parse_arguments({("location"):"$pc"},{"--set": "", "--monitor": True, "--print": True, "--clear": True}) # kwarg사용시 필요, --???시 True로 초기화됨
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        # 1. module없을 경우 자동 설치
        import_or_install("capstone") 
        
        # 2. args 값 가져오는 것
        args = kwargs["arguments"]
        print(args)
        
        sys.exit()
        
        # 3. 입력한 location과 REG가 해당 범위를 벗어나지 않는지 체크
        
        # (+) 추가기능 : --monitor, --print, --clear같은 기능들은 주요 기능 실행 전에 여기서 체크후 기능실행
        
        # 4. length 필수인데 입력하는게 아닌 자동으로 수집 해야함 -> CS에서 쓰임
        length = args.length or gef.config["context.nb_lines_code"] # or : bit연산자 , config : 6
        location = parse_address(args.location) #int값 반환
        code_section = []
        
        '''
        # 코드영역 주소 추출하는 코드(임시)
        def export_location_opcode_value():
            vmmap = gef.memory.maps
            if not vmmap:
                err("No address mapping information found")
                return

            #print(f"start\t\tend\t\toffset\t\tperm\t\tPath")
            # code영역 주소 추출
            for entry in vmmap:
                if "/usr/lib/x86_64-linux-gnu/libc.so.6" in entry.path:
                    break
                l = [hex(entry.page_start),hex(entry.page_end),hex(entry.offset),str(entry.permission),str(entry.path)]
                code_section.append(l)
                del l
                #print(f"{hex(entry.page_start)}\t{hex(entry.page_end)}\t{hex(entry.offset)}\t\t{entry.permission}\t\t{entry.path}")
            start_codeaddr = code_section[0][0] # 시작
            end_codeaddr = code_section[len(code_section)-1][1] #마지막
            

            #color = gef.config["theme.table_heading"]
            #headers = ["Start", "End", "Offset", "Perm", "Path"]
            #gef_print(Color.colorify("{:<{w}s}{:<{w}s}{:<{w}s}{:<4s} {:s}".format(*headers, w=gef.arch.ptrsize*2+3), color))
        
        export_location_opcode_value()
        '''
        
        # 주소 여부 확인 -> 3번으로 추후 옮김
        if not location:
            info(f"Can't find address for {args.location}")
            return
        
        # 5. 디스어셈블리
        insns = [] # INSTRUCTION 클래스가 들어감
        opcodes_len = 0
        for insn in cs_disassemble(location, length, skip=length * self.repeat_count, **kwargs): # DISASSEMBLY 핵심
            insns.append(insn)
            opcodes_len = max(opcodes_len, len(insn.opcodes)) # ?
        # confirm_inst(insns[0])
        
        # 6. 쓰레드 백그라운드로 매번 확인후 $PC가 바뀌었을때 오염검사 진행
        # => 오염이 됬다면 GEF_PRINTR같은것으로 자동 호출
        
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

'''
[추가 기능]
—set “레지스터” => 오염될 레지스터 설정
<기본값 : None>

—monitor True=> 오염이 발생될 때 gef_print, gef_info발생 (백그라운드로 계속 확인) / False는 종료
=> 쓰레드로 돌릴 예정

—print => 오염된 사양 다 출력

—clear => 기존에 오염과 지정한 레지스터 다 삭제
'''