from typing import List, Optional
from pydantic import BaseModel, Field, ValidationError, validator, IPvAnyAddress
from typing import Optional
from datetime import datetime
import re
from uuid import UUID


class ExecutionCategory(BaseModel):
    name: str
    abbreviation: str


class ProcedureId(BaseModel):
    type: str
    id: str


class AttireTarget(BaseModel):
    host: Optional[str]
    ip_address: IPvAnyAddress = None

    class Config:
        validate_assignment = True


class ExecutionData(BaseModel):
    command: str = Field(alias="execution-command")
    id: str = Field(alias="execution-id")
    source: str = Field(alias="execution-source")
    category: Optional[ExecutionCategory] = Field(alias="execution-category")
    target: Optional[AttireTarget]
    time_generated: Optional[str] = Field(alias="time-generated")

    class Config:
        allow_population_by_field_name = True
        validate_assignment = True


class OutputItem(BaseModel):
    content: str
    level: str
    type: str


class ProcedureId(BaseModel):
    type: str
    uuid: UUID

    class Config:
        validate_assignment = True


class Step(BaseModel):
    command: Optional[str]
    executor: Optional[str]
    order: Optional[int]
    output: Optional[OutputItem]
    time_start: Optional[str] = Field(alias="time-start")
    time_stop: Optional[str] = Field(alias="time-stop")

    class Config:
        allow_population_by_field_name = True

    @validator('time_start', 'time_stop', pre=True, allow_reuse=True)
    def parse_foobar(cls, v) -> str:
        if isinstance(v, str):
            test = str(datetime.strptime(v, '%Y-%m-%dT%H:%M:%S.%fZ'))[:-3] + 'Z'
            print('TimeDate Format :' + test)
            return test
        return v

    # @validator('time_start', pre=True, allow_reuse=True)
    # def validate_timestamp(cls, v: datetime) -> str:
    #     time_format = v.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    #     return time_format    


class Procedure(BaseModel):
    procedure_name: Optional[str] = Field(alias="procedure-name")
    procedure_description: Optional[str] = Field(alias="procedure-description")
    procedure_id: Optional[ProcedureId] = Field(alias="procedure-id")
    mitre_technique_id: Optional[str] = Field(alias="mitre-technique-id")
    orders: Optional[str]
    steps: List[Step] = []

    class Config:
        allow_population_by_field_name = True
        validate_assignment = True

    @validator('mitre_technique_id')
    def mitre_id_format(cls, v):
        mitre_id = ("^(T\d{4})(\.\d{3})?$")
        if not re.match(mitre_id, v):
            return ValueError("Mitre Technique Is Incorrect")
        return v.title()


class AttireLog(BaseModel):
    attire_version: Optional[str] = Field(alias="attire-version")
    execution_data: Optional[ExecutionData] = Field(alias="execution-data")
    procedures: List[Procedure] = []

    class Config:
        allow_population_by_field_name = True
