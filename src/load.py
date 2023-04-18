import os
import sys
import gdb

class load(GenericCommand):
    """Dummy new command."""
    _cmdline_ = "load"
    #_syntax_  = f"{_cmdline_}"
    _syntax_ = f"{_cmdline_} [file_name]"

    @only_if_gdb_running
    @parse_arguments({("file_name"):""},{}) # kwarg사용시 필요, --???시 True로 초기화됨
    def do_invoke(self, _: List[str], **kwargs: Any) -> None:
        
        # load할 파일을 무조건 지정해야함
        args = kwargs["arguments"]
        set_file = args.file_name
        
        if set_file == "":
            gef_print("[!] load할 파일을 지정해주세요")
            return
        
        else:
            if os.path.exists(set_file):
                # file이 존재할 경우
                command = "source " + set_file
                gdb.execute(command)
                
            else:
                # file이 없는 경우
                gef_print("[!] file이 존재하지 않습니다.")
                return
        
        return

register_external_command(load())