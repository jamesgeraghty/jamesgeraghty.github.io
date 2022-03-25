import socket

from datetime import datetime
import re
from uuid import UUID

from attire_logger_schemas import ExecutionCategory, ExecutionData, AttireLog, AttireTarget, Procedure, ProcedureId \
    , Step, OutputItem

test_log = AttireLog(attire_version='1.1')

# test_log.add execution data
target = AttireTarget(host="WINDEV2009EVAL")

# Get the Host IP Address
hostname = socket.gethostname()
host_ip = socket.gethostbyname(hostname)
ip = host_ip
target.ip_address = host_ip

# Object instantiation
exec_category = ExecutionCategory(name="Atomic Red Team", abbreviation="ART")
exec_data = ExecutionData(command='Invoke-AtomicTest', id='3im2GxwX9VG8jzXLTDegLEKY8WfrA1IXL0VUwhlDYWs=',
                          source='Invoke-Atomicredteam')

# Time Generated Move to validation
current_utc = datetime.utcnow()
exec_data.time_generated = current_utc.isoformat("T")[:-3] + "Z"

exec_data.category = exec_category
exec_data.target = target
proc_id = ProcedureId(type='guid', uuid='c9d0c4ef-8a96-4794-a75b-3d3a5e6f2a36')

step = Step(command='powershell', executor='Powershell', order='1', time_start='2022-01-25T15:33:18.122Z'
            , time_stop='2021-10-27T02:02:25.122Z')

out_put = OutputItem(content='123', level='123', type='Console')
output_list = [out_put]
step_list = [step]
procedure_data = Procedure(procedure_name='Regsvr32 remote COM scriptlet execution'
                           , procedure_description='Run an exe on user logon or system startup.',
                           mitre_technique_id='T1218.000', orders='1')
procedures = [procedure_data]
procedure_data.procedure_id = proc_id
procedure_data.steps = [step]
step.output = [out_put]
output1 = OutputItem(content='test', level='level1', type='type')
output = [output1]
test_log.procedures = procedures
test_log.execution_data = exec_data

test_logjson = test_log.json(indent=4, by_alias=True)

print(test_logjson)
with open("Attire-logger-module/attire_logger-v5.json", "w") as f:
    f.write(test_logjson)
