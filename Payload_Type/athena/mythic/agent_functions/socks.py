from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *

class SocksArguments(TaskArguments):

    valid_actions = ["start", "stop"]
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line)
        self.args = [
            CommandParameter(
                name="action",
                choices=["start","stop"],
                type=ParameterType.ChooseOne,
                description="Start or stop the socks server.",
                parameter_group_info=[ParameterGroupInfo(ui_position=1)],
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                description="Port to start the socks server on.",
                parameter_group_info=[ParameterGroupInfo(ui_position=2)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must be passed \"start\" or \"stop\" commands on the command line.")
        try:
            self.load_args_from_json_string(self.command_line)
        except:
            parts = self.command_line.lower().split()
            action = parts[0]
            if action not in self.valid_actions:
                raise Exception("Invalid action \"{}\" given. Require one of: {}".format(action, ", ".join(self.valid_actions)))
            self.add_arg("action", action)
            if action == "start":
                port = -1
                if len(parts) < 2:
                    port = 3333
                else:
                    try:
                        port = int(parts[1])
                    except Exception as e:
                        raise Exception("Invalid port number given: {}. Must be int.".format(parts[1]))
                self.add_arg("port", port, ParameterType.Number)

#Pretty much the exactly socks.py from Apollo by @Djhonstein
class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks [action] [port number]"
    description = "Enable SOCKS 5 compliant proxy on the agent to browse internal resources."
    version = 1
    is_exit = False
    is_file_browse = False
    is_process_list = False
    is_download_file = False
    is_upload_file = False
    is_remove_file = False
    author = "@checkymander"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(
        load_only=False,
        builtin=True
    )

    async def create_tasking(self, task: MythicTask) -> MythicTask:
        if task.args.get_arg("action") == "start":
            resp = await MythicRPC().execute("control_socks",
                                             task_id=task.id,
                                             start=True,
                                             port=task.args.get_arg("port"))
        else:
            resp = await MythicRPC().execute("control_socks",
                                             task_id=task.id,
                                             stop=True,
                                             port=task.args.get_arg("port"))
        if resp.status == MythicStatus.Success:
            return task
        else:
            task.status = MythicStatus.Error
        task.display_params = "{} {}".format(task.args.get_arg("action"), task.args.get_arg("port"))
        return task

    async def process_response(self, response: AgentResponse):
        pass
