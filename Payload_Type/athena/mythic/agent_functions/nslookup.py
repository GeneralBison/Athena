from mythic_payloadtype_container.MythicCommandBase import *
import json
from mythic_payloadtype_container.MythicRPC import *


class NslookupArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line)
        self.args = [
            CommandParameter(
                name="hosts",
                type=ParameterType.String,
                description="Comma separate list of hosts",
            ),
            CommandParameter(
                name="inputlist",
                type=ParameterType.File,
                description="List of hosts in a newline separated file",
                parameter_group_info=[ParameterGroupInfo(
                    required=True,
                    group_name="TargetLIst"
                )]
            )
        ]

    async def parse_arguments(self):
        if len(self.command_line) > 0:
            if self.command_line[0] == "{":
                self.load_args_from_json_string(self.command_line)
            else:
                self.add_arg("hosts", self.command_line)
        else:
            raise ValueError("Missing arguments")


class NsLookupCommand(CommandBase):
    cmd = "nslookup"
    needs_admin = False
    help_cmd = "nslookup DC1.gaia.local,FS1.gaia.local,gaia.local"
    description = "Perform an nslookup on the provided hosts"
    version = 1
    author = "@checkymander"
    argument_class = NslookupArguments
    attackmapping = ["T1106"]
    attributes = CommandAttributes(
        load_only=True
    )
    async def create_tasking(self, task: MythicTask) -> MythicTask:
        groupName = task.args.get_parameter_group_name()
        if groupName == "TargetList":
            file_resp = await MythicRPC().execute("get_file",
                                                  file_id=task.args.get_arg("inputlist"),
                                                  task_id=task.id,
                                                  get_contents=True)
            if file_resp.status == MythicRPCStatus.Success:
                if len(file_resp.response) > 0:
                    task.args.add_arg("targetlist", file_resp.response[0]["contents"],
                                      parameter_group_info=[ParameterGroupInfo(group_name="Default")])
                    #task.display_params = f"{file_resp.response[0]['filename']}"
                else:
                    raise Exception("Failed to find that file")
            else:
                raise Exception("Error from Mythic trying to get file: " + str(file_resp.error))
        else:
            return task

    async def process_response(self, response: AgentResponse):
        pass
