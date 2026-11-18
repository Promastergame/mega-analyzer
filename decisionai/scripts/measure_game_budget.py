import argparse, base64, ctypes, http.client, json, os, pathlib, socket, statistics, struct, subprocess, time, zlib
from ctypes import wintypes

root = pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description='Measure the light DecisionAI process on Windows.')
parser.add_argument('--game',choices=['tic_tac_toe','tetris','russian_checkers'],default='tic_tac_toe')
parser.add_argument('--binary',default='.tmp/dai-visual-games.exe',help='Executable path relative to the project, or absolute.')
options=parser.parse_args()
out = root / '.tmp' / 'game-budget'
out.mkdir(exist_ok=True)
size = 300
rows = ['XX.', 'OO.', '...']
raw = bytearray()
for y in range(size):
    raw.append(0)
    for x in range(size):
        ink = any(abs(v - p) < 2 for v in (x, y) for p in (100, 200))
        xf, yf = ((x % 100)/100-.5)/.6+.5, ((y % 100)/100-.5)/.6+.5
        if 0 <= xf <= 1 and 0 <= yf <= 1:
            mark = rows[y//100][x//100]
            ink |= mark == 'X' and (abs(xf-yf)<.12 or abs(xf+yf-1)<.12)
            ink |= mark == 'O' and abs(((xf-.5)**2+(yf-.5)**2)**.5-.43)<.075
        raw.extend((0,0,0) if ink else (255,255,255))
def chunk(kind, data):
    return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data))
png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',size,size,8,2,0,0,0))+chunk(b'IDAT',zlib.compress(raw))+chunk(b'IEND',b'')
(out/'board.png').write_bytes(png)
image={'data':base64.b64encode(png).decode(),'mime_type':'image/png'}
payload=json.dumps({'game':'tic_tac_toe','image':image}).encode()
(out/'image-game.json').write_bytes(payload)
scenario='300x300 RGB PNG; detect board and calculate move via HTTP'
if options.game!='tic_tac_toe':
    scenario=options.game+'; arena PNG -> recognize board/active piece/turn -> move via HTTP'

class Counters(ctypes.Structure):
    _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD)]+[(n,ctypes.c_size_t) for n in ('PeakWorkingSetSize','WorkingSetSize','QuotaPeakPagedPoolUsage','QuotaPagedPoolUsage','QuotaPeakNonPagedPoolUsage','QuotaNonPagedPoolUsage','PagefileUsage','PeakPagefileUsage','PrivateUsage')]
psapi=ctypes.WinDLL('psapi',use_last_error=True)
psapi.GetProcessMemoryInfo.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
kernel=ctypes.WinDLL('kernel32',use_last_error=True)
kernel.GetProcessTimes.argtypes=[wintypes.HANDLE]+[ctypes.POINTER(wintypes.FILETIME)]*4
def usage(proc):
    mem=Counters();mem.cb=ctypes.sizeof(mem)
    if not psapi.GetProcessMemoryInfo(int(proc._handle),ctypes.byref(mem),mem.cb): raise ctypes.WinError(ctypes.get_last_error())
    ts=[wintypes.FILETIME() for _ in range(4)]
    if not kernel.GetProcessTimes(int(proc._handle),*[ctypes.byref(t) for t in ts]): raise ctypes.WinError(ctypes.get_last_error())
    cpu=sum((t.dwHighDateTime<<32)+t.dwLowDateTime for t in ts[2:])/1e7
    return cpu,mem

sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1];sock.close()
env=dict(os.environ,DAI_API_TOKEN='local-budget-test-token')
with (out/'server.log').open('w') as log:
    proc=subprocess.Popen([str(root/options.binary),'serve','-light','-addr',f'127.0.0.1:{port}'],cwd=root,env=env,stdout=log,stderr=log,creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        for _ in range(100):
            try:
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5);conn.request('GET','/v1/health');res=conn.getresponse();res.read();conn.close();break
            except OSError: time.sleep(.1)
        else: raise RuntimeError('server did not start')
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
        if options.game!='tic_tac_toe':
            conn.request('POST','/v1/arena',json.dumps({'command':'new','game':options.game}),{'Content-Type':'application/json','Authorization':'Bearer local-budget-test-token'})
            res=conn.getresponse();frame=json.loads(res.read())
            if res.status!=200: raise RuntimeError(frame)
            # A visible midgame; the solver receives PNG only, including setup moves.
            first_image_ms=None
            for setup_index in range(8):
                initial_start=time.perf_counter()
                conn.request('POST','/v1/game',json.dumps({'game':options.game,'image':frame['image']}),{'Content-Type':'application/json','Authorization':'Bearer local-budget-test-token'})
                res=conn.getresponse();decision=json.loads(res.read())
                if setup_index==0: first_image_ms=(time.perf_counter()-initial_start)*1000
                if res.status!=200 or decision.get('source')!='image': raise RuntimeError(decision)
                move={'controls':decision['controls']} if options.game=='tetris' else {'path':decision['path']}
                conn.request('POST','/v1/arena',json.dumps({'command':'apply','revision':frame['revision'],'decision':move}),{'Content-Type':'application/json','Authorization':'Bearer local-budget-test-token'})
                res=conn.getresponse();frame=json.loads(res.read())
                if res.status!=200: raise RuntimeError(frame)
            payload=json.dumps({'game':options.game,'image':frame['image']}).encode()
            (out/(options.game+'-image.json')).write_bytes(payload)
            (out/(options.game+'-image.png')).write_bytes(base64.b64decode(frame['image']['data']))
        def call(body):
            begin=time.perf_counter();conn.request('POST','/v1/game',body,{'Content-Type':'application/json','Authorization':'Bearer local-budget-test-token'});res=conn.getresponse();data=json.loads(res.read());ms=(time.perf_counter()-begin)*1000
            if res.status!=200 or not data.get('action'): raise RuntimeError((res.status,data))
            if options.game!='tic_tac_toe' and data.get('source')!='image': raise RuntimeError('not an image decision')
            if options.game=='tetris' and (not data.get('controls') or not data.get('placement')): raise RuntimeError('missing tetris controls')
            if options.game=='russian_checkers' and len(data.get('path',[]))<2: raise RuntimeError('missing checker path')
            return ms
        cold=call(payload)
        if options.game!='tic_tac_toe': cold=first_image_ms
        for _ in range(5): call(payload)
        cpu0,_=usage(proc);wall0=time.perf_counter();times=[]
        # Two image-to-move cycles per second, matching the default MCP pace.
        for i in range(24):
            target=wall0+i*.5
            time.sleep(max(0,target-time.perf_counter()))
            times.append(call(payload))
        elapsed=time.perf_counter()-wall0;cpu1,mem=usage(proc)
        board=json.dumps({'game':'tic_tac_toe','board':['...','...','...']}).encode()
        empty=[call(board) for _ in range(30)] if options.game=='tic_tac_toe' else []
        report={'profile':'dai serve -light','game':options.game,'logical_cpus':os.cpu_count(),'scenario':scenario,'requests_per_second':2,'samples':len(times),'cold_http_ms':round(cold,3),'http_p50_ms':round(statistics.median(times),3),'http_p95_ms':round(sorted(times)[int(len(times)*.95)-1],3),'http_max_ms':round(max(times),3),'cpu_percent_of_machine':round((cpu1-cpu0)/elapsed/os.cpu_count()*100,3),'working_set_mb':round(mem.WorkingSetSize/1e6,3),'peak_working_set_mb':round(mem.PeakWorkingSetSize/1e6,3),'private_mb':round(mem.PrivateUsage/1e6,3),'scope':'DecisionAI process only; startup CPU, browser and external MCP server not included; no hard OS quota'}
        if empty: report['empty_board_p95_ms']=round(sorted(empty)[int(len(empty)*.95)-1],3)
        report_name='report.json' if options.game=='tic_tac_toe' else options.game+'-report.json'
        (out/report_name).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps(report,ensure_ascii=False,indent=2))
        conn.close()
    finally:
        proc.terminate();proc.wait(timeout=10)
