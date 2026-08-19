from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List
from app.services import network_utils

router = APIRouter(prefix="/api/network", tags=["Network Utilities"])

class TargetRequest(BaseModel):
    target: str

class PingSweepRequest(BaseModel):
    base_ip: str
    start: int = 1
    end: int = 50

class PortScanRequest(BaseModel):
    target: str
    ports: List[int]

class WhoisRequest(BaseModel):
    target: str

class MacRequest(BaseModel):
    mac: str

class SubnetRequest(BaseModel):
    cidr: str

@router.post("/ping")
async def ping_target(req: TargetRequest):
    result = await network_utils.async_ping(req.target, count=4)
    return result

@router.post("/ping-sweep")
async def ping_sweep(req: PingSweepRequest):
    if req.end - req.start > 254:
        raise HTTPException(status_code=400, detail="Sweep range cannot exceed 254 hosts.")
    active_hosts = await network_utils.async_ping_sweep(req.base_ip, req.start, req.end)
    return {"base_subnet": req.base_ip, "active_hosts": active_hosts}

@router.post("/scan-ports")
async def scan_ports(req: PortScanRequest):
    if len(req.ports) > 1024:
        raise HTTPException(status_code=400, detail="Cannot scan more than 1024 ports in a single request.")
    open_ports = await network_utils.async_port_scan(req.target, req.ports)
    return {"target": req.target, "open_ports": open_ports}

# @router.post("/traceroute")
# async def traceroute_target(req: TargetRequest):
#     hops = await network_utils.async_traceroute(req.target)
#     return {"target": req.target, "hops": hops}

@router.post("/dns-lookup")
async def dns_lookup(req: TargetRequest):
    records = await network_utils.async_dns_lookup(req.target)
    return {"target": req.target, "records": records}

@router.post("/whois")
async def get_whois(req: WhoisRequest):
    return await network_utils.async_whois_lookup(req.target)

@router.post("/mac-lookup")
async def get_mac_vendor(req: MacRequest):
    return await network_utils.async_mac_lookup(req.mac)

@router.post("/subnet-calc")
async def get_subnet_details(req: SubnetRequest):
    return network_utils.calculate_subnet(req.cidr)

@router.post("/ssl-check")
async def check_ssl(req: TargetRequest):
    return await network_utils.async_ssl_check(req.target)
