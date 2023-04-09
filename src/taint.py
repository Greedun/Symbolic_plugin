import importlib
import os
import sys

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


# 코드영역 주소 추출하는 코드(임시)
def export_location_opcode_value():
    code_section = []
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
    return [start_codeaddr,end_codeaddr]

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

def check_location(location):
    code_section = export_location_opcode_value() # 코드 영역 경계(리스트)
    code_start = int(code_section[0],16)
    code_end = int(code_section[1],16)
    
    if location < code_start and location > code_end:
        return False
    
    return True

def check_flag(list_flag):
    # print : location의 기본 기능
    # [monitor_flag, set_flag, clear_flag] - 4, 2, 1
    # 순위 : clear -> set -> monitor
    # clear => TaintReg --clear
    # set => TaintReg location($pc) --set Reg
    # monitor => TaintReg --monitor
    status = ""
    if list_flag[0] == True: # monitor
        status += "1"
    else:
        status += "0"
    
    if list_flag[1] != "": # set
        status += "1"
    else:
        status += "0"
    
    if list_flag[2] == True: # clear
        status += "1"
    else:
        status += "0"
    
    return status

# 기능별 함수 구분
def function_set(location, list_result_ds, set_flag):
    # 지정한 REG가 현재 혹은 지정한 location에 있는지 확인하는 작업
    # 디스어셈블리 -----------------------
    insns = [] # INSTRUCTION 클래스가 들어감
    opcodes_len = 0
    length = 1
    for insn in list_result_ds: # DISASSEMBLY 핵심
        insns.append(insn)
        opcodes_len = max(opcodes_len, len(insn.opcodes)) # ?
    
    show_opcodes = True
    insn = insns[0]
    dict_insn = {}
    dict_key = ['addr','opcode','location','inst','semantic']
    dict_insn['semantic'] = []
    
    insn_fmt = f"{{:{opcodes_len}o}}" if show_opcodes else "{}"
    text_insn = insn_fmt.format(insn)
    list_insn = list(filter(lambda x: x!='',text_insn.split(" "))) # ''는 리스트에서 필터링처리
    for i in range(len(list_insn)):
        if i < 4:
            dict_insn[dict_key[i]]=list_insn[i]
        else:
            list_insn[i] = list_insn[i].replace(',','')
            dict_insn['semantic'].append(list_insn[i])

    # ----------
    exist_REG = 0 # 해당 주소에 REG확인하는 변수
    # set할 레지스터에 있는지 확인
    for semantic in dict_insn['semantic']:
        if semantic == set_flag.lower():
            exist_REG += 1

    if exist_REG == 0:
        gef_print("[!] 오염시킬 주소에 해당 레지스터는 존재하지 않습니다.")
        return
    
    taint_REG = set_flag
    print("test")
    
    return

def function_clear():
    total_taint = []
    taint_REG = None
    
    return

def function_monitoring():
    
    return

# taint_progress파일 관련
def check_taint_progress():
    if not os.path.exists("taint_progress"):
        open("taint_progress", 'w')
        
        # Frame을 해당 파일에 적기(json형태)
        
        gef_print("[+] Create 'taint_progress' file")

# 코드 마무리시 여태까지 기록을 업데이트하는 기능
def finish_taint_progress():
    pass
    
# -------------------------

# (1) hook을 통해 gdb가 bp될때마다 실행되게 하는 방법을 찾아서 먼저 시도 예정
# (2) (gdb내부에서 자동실행 안될경우) 내부 진행사항이 유지가 안되기 때문에 "taint_progress"란 파일을 토대로 진행되게 할 것
class Taint_Reg(GenericCommand):
    
    """Dummy new command."""
    _cmdline_ = "TaintReg"
    _syntax_  = f"{_cmdline_} [location] [--set] [--monitor] [--clear]"
    
    # location 지정 없을때 $pc에 있는 레지스터 / location 지정 있을때 location에 있는 레지스터
    @only_if_gdb_running
    @parse_arguments({("location"):"$pc"},{"--set": "", "--monitor": True, "--clear": True}) # kwarg사용시 필요, --???시 True로 초기화됨
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:

        # 1. module없을 경우 자동 설치
        import_or_install("capstone")
        
        # 2. args 값 가져오는 것
        args = kwargs["arguments"]
        set_flag = args.set
        monitor_flag = args.monitor
        clear_flag = args.clear
        list_flag = [monitor_flag, set_flag, clear_flag]
        
        # 3. check flag -> status
        list_status = list(check_flag(list_flag))
        
        # 4. location값 설정
        if args.location == "$pc":
            location = parse_address(args.location) # int값
        else:
            location = int(args.location,16)
        
        # 3-1. location 검증
        if check_location(location): #location범위 확인하는 함수
            # 기록할 파일 존재여부 확인후 생성
            check_taint_progress()
            
            # "taint_progress"란 파일이 존재한다면 -> 진행사항 가져오기
            # 없다면 새로 생성후 frame구축
            
            # 5. status 값에 따른 기능 수행
            if list_status[0] == "1":
                # clear 기능
                # => 값에 대한 초기화 기능
                # => 내부값을 유지할 방법이 없으니 "taint_progress"파일을 삭제하는 방법으로 대체
                function_clear()
            
            if list_status[1] == "1":
                # set 기능
                insns = [] # INSTRUCTION 클래스가 들어감
                opcodes_len = 0
                length = 1
                list_result_ds = cs_disassemble(location, length, skip=length * self.repeat_count, **kwargs) # DISASSEMBLY 핵심
                
                function_set(location, list_result_ds, set_flag)
                
                
            if list_status[2] == "1":
                # monitoring 기능
                function_monitoring()
            
        else:
            # code section 주소가 아닌 경우
            gef_print("[!] Code Section 범위의 주소입니다.")
            return
        
        finish_taint_progress() # Last
        
        return
    
        # 6. 쓰레드 백그라운드로 매번 확인후 $PC가 바뀌었을때 오염검사 진행
        # => 오염이 됬다면 GEF_PRINTR같은것으로 자동 호출
        # (+) 추가기능 : --monitor, --print, --clear같은 기능들은 주요 기능 실행 전에 여기서 체크후 기능실행
        
    
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