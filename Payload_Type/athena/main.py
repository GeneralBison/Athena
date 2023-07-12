import mythic_container
from athena.mythic import *
import subprocess

p = subprocess.Popen(["dotnet", "restore"], cwd="/Mythic/athena/agent_code/AthenaPlugins")
p = subprocess.Popen(["dotnet", "msbuild", "-m", "/consoleloggerparameters:ErrorsOnly" "--verbosity=q", "--nologo"], cwd="/Mythic/athena/agent_code/AthenaPlugins")

mythic_container.mythic_service.start_and_run_forever()