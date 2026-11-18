"use strict";
// Ports connect the coordinator directly to its independent file scanners.
// The bridge owns all Worker lifetimes, including Stop and timeout cleanup.
class MegaFilePool {
  constructor(ports) {
    this.completed=0;
    this.slots = ports.map(port => ({port, busy:false, alive:true, id:null, completed:0}));
    for (const slot of this.slots) {
      slot.port.onmessage = ({data}) => {
        if (data.type !== "file-result" || data.id !== slot.id) return;
        const id=slot.id;slot.id=null;slot.busy=false;
        this.completed++;slot.completed++;
        if(data.error)slot.alive=false;
        self.megaFileScanDone(id, data.result || "{}", data.error || "");
      };
      slot.port.start();
    }
    self.megaFileScanAvailable = () => this.slots.some(slot => slot.alive && !slot.busy);
    self.megaFileScan = (id,configuration,metadata,content) => {
      const slot=this.slots.find(slot => slot.alive && !slot.busy);
      if(!slot)return false;
      slot.busy=true;slot.id=id;
      try {
        slot.port.postMessage({type:"file-scan",id,configuration,metadata,content},[content.buffer]);
        return true;
      } catch {
        slot.alive=false;slot.busy=false;slot.id=null;return false;
      }
    };
  }
  close() { for(const slot of this.slots){slot.alive=false;slot.port.close();} }
}
self.MegaFilePool=MegaFilePool;
