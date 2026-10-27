package api

// indexHTML is the control panel served at /. It is self-contained (no
// external assets, so it works on a Pi with no internet) and drives the
// JSON API: GET /status, POST /command.
const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Pod simulator</title>
<style>
  :root { color-scheme: dark; --bg:#14161a; --card:#1d2026; --line:#2b2f37; --fg:#e8eaed; --mut:#9aa0aa; --accent:#4f9cf8; --ok:#43c06d; --warn:#e0a53b; --bad:#e2574c; }
  * { box-sizing:border-box; }
  body { margin:0; font:15px/1.4 -apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--fg); }
  header { padding:16px; border-bottom:1px solid var(--line); display:flex; flex-wrap:wrap; gap:4px 20px; align-items:baseline; }
  header h1 { font-size:18px; margin:0; }
  header .meta { color:var(--mut); font-size:13px; }
  main { max-width:760px; margin:0 auto; padding:16px; display:grid; gap:16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; }
  .card h2 { font-size:13px; text-transform:uppercase; letter-spacing:.05em; color:var(--mut); margin:0 0 12px; }
  .big { display:flex; align-items:baseline; gap:12px; flex-wrap:wrap; }
  .big .val { font-size:44px; font-weight:600; }
  .big .unit { color:var(--mut); }
  .chip { padding:3px 10px; border-radius:20px; font-size:13px; background:#2b2f37; }
  .big .chip { margin-left:auto; }
  .chip.ok { background:rgba(67,192,109,.18); color:var(--ok); }
  .chip.warn { background:rgba(224,165,59,.18); color:var(--warn); }
  .chip.bad { background:rgba(226,87,76,.18); color:var(--bad); }
  dl { display:grid; grid-template-columns:max-content 1fr; gap:6px 16px; margin:14px 0 0; }
  dt { color:var(--mut); }
  dd { margin:0; }
  label { display:block; font-size:13px; color:var(--mut); margin:10px 0 4px; }
  input[type=number], select { width:100%; padding:8px; background:#14161a; border:1px solid var(--line); border-radius:7px; color:var(--fg); font-size:15px; }
  .row { display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end; }
  .row > div { flex:1; min-width:140px; }
  .checks { display:grid; grid-template-columns:repeat(auto-fill,minmax(210px,1fr)); gap:6px 16px; }
  .checks label { display:flex; gap:8px; align-items:center; margin:0; font-size:14px; color:var(--fg); }
  .actions { margin-top:14px; display:flex; flex-wrap:wrap; align-items:center; gap:8px 12px; }
  button { padding:9px 14px; background:#2b2f37; color:var(--fg); border:1px solid var(--line); border-radius:7px; font-size:14px; cursor:pointer; }
  button:hover { border-color:var(--accent); }
  button:focus-visible, input:focus-visible, select:focus-visible { outline:2px solid var(--accent); outline-offset:1px; }
  button.primary { background:var(--accent); border-color:var(--accent); color:#0b0d10; font-weight:600; }
  button.danger:hover { border-color:var(--bad); }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); }
  th { color:var(--mut); font-weight:500; }
  .muted { color:var(--mut); font-size:13px; }
  footer { max-width:760px; margin:0 auto; padding:4px 16px 24px; color:var(--mut); font-size:12px; }
</style>
</head>
<body>
<header>
  <h1 id="title">Pod</h1>
  <span class="meta" id="podid"></span>
  <span class="meta" id="controller"></span>
  <span class="chip" id="link" role="status">—</span>
</header>
<main>
  <section class="card" aria-labelledby="h-status">
    <h2 id="h-status">Pod</h2>
    <div class="big">
      <span class="val" id="reservoir">—</span>
      <span class="unit" id="reservoirUnit">U in reservoir</span>
      <span class="chip" id="progress">—</span>
    </div>
    <dl>
      <dt>Delivered</dt><dd id="delivered">—</dd>
      <dt>Pod age</dt><dd id="age">—</dd>
      <dt>Basal</dt><dd id="basal">—</dd>
      <dt>Temp basal</dt><dd id="temp">—</dd>
      <dt>Bolus</dt><dd id="bolus">—</dd>
      <dt>Alerts</dt><dd id="alertsNow">—</dd>
      <dt>Fault</dt><dd id="faultNow">—</dd>
    </dl>
  </section>

  <section class="card" aria-labelledby="h-res">
    <h2 id="h-res">Reservoir</h2>
    <div class="row">
      <div><label for="resIn">Units in the reservoir (0–200)</label><input type="number" id="resIn" min="0" max="200" step="0.05"></div>
      <div style="flex:0"><button class="primary" id="resSet">Set</button></div>
    </div>
    <div class="muted" style="margin-top:8px">The pod reports the level only below 50 U; above that it reports “50+ U”.</div>
  </section>

  <section class="card" aria-labelledby="h-age">
    <h2 id="h-age">Pod age</h2>
    <div class="row">
      <div><label for="ageIn">Hours since activation</label><input type="number" id="ageIn" min="0" max="100" step="0.25"></div>
      <div style="flex:0"><button class="primary" id="ageSet">Set</button></div>
    </div>
    <div class="actions">
      <span class="muted">Jump to:</span>
      <button data-hours="71.5">71.5 h</button>
      <button data-hours="72">72 h (expires)</button>
      <button data-hours="79">79 h</button>
      <button data-hours="80">80 h (shuts down)</button>
    </div>
    <div class="muted" style="margin-top:8px">At 80 hours the pod faults with 0x1C at the next command.</div>
  </section>

  <section class="card" aria-labelledby="h-alerts">
    <h2 id="h-alerts">Active alerts</h2>
    <div class="checks" id="alertChecks"></div>
    <div class="actions"><button class="primary" id="alertsSet">Set alerts</button></div>
  </section>

  <section class="card" aria-labelledby="h-fault">
    <h2 id="h-fault">Fault</h2>
    <label for="faultIn">Fault code</label>
    <select id="faultIn"></select>
    <div class="actions">
      <button class="danger" id="faultSet">Trigger fault</button>
      <button id="faultClear">Clear fault</button>
    </div>
  </section>

  <section class="card" aria-labelledby="h-crash">
    <h2 id="h-crash">Unacknowledged command</h2>
    <div class="actions" style="margin-top:0">
      <button class="danger" id="crashBefore">Crash before processing next command</button>
      <button class="danger" id="crashAfter">Crash after processing next command</button>
    </div>
    <div class="muted" style="margin-top:8px" id="crashNote">The simulator exits at the next command that changes delivery, leaving the phone without a response. Restart it (run.sh does) to see how the app recovers.</div>
  </section>

  <section class="card" aria-labelledby="h-comms">
    <h2 id="h-comms">Comms</h2>
    <table><tbody>
      <tr><th scope="row">Message sequence</th><td id="msgSeq">—</td></tr>
      <tr><th scope="row">Command sequence</th><td id="cmdSeq">—</td></tr>
      <tr><th scope="row">Nonce sequence</th><td id="nonceSeq">—</td></tr>
      <tr><th scope="row">EAP-AKA sequence</th><td id="eapSeq">—</td></tr>
      <tr><th scope="row">Last programming sequence</th><td id="progSeq">—</td></tr>
      <tr id="sigRow" hidden><th scope="row">Signed commands rejected</th><td id="badSigs">—</td></tr>
    </tbody></table>
  </section>
  <div class="muted" id="msg" role="status" aria-live="polite"></div>
</main>
<footer>For development use only — not an Insulet product. This pod simulates delivery; never use it for therapy.</footer>
<script>
const ALERTS = ["Auto-off","Unused","Shutdown imminent","Expiration reminder","Low reservoir","Suspended reminder","Suspend expired","Lifecycle"];
const FAULTS = [
  [1,"Flash erase failed"],
  [2,"Flash store failed"],
  [3,"Basal subcommand table corruption"],
  [5,"Basal step corruption"],
  [6,"RTC interrupt or pump encoder table corruption"],
  [7,"Wire overdriven timeout"],
  [8,"Invalid beep value"],
  [9,"Invalid beep repeat pattern value"],
  [10,"Temp basal step corruption"],
  [11,"Temp basal subcommand table corruption"],
  [13,"Reset due to COP"],
  [14,"Reset due to illegal opcode"],
  [15,"Reset due to illegal address"],
  [16,"Reset due to SAWCOP Safety check"],
  [17,"Bolus step corruption"],
  [18,"Reset due to Low Voltage Detect"],
  [19,"Message length too long"],
  [20,"Occluded Reported as \"Occlusion detected\""],
  [21,"Bolus program corruption"],
  [22,"Bolus log corruption Safety check"],
  [23,"Corruption in a validated table"],
  [24,"Reservoir empty or exceeded maximum pulse delivery Reported as \"Empty reservoir\""],
  [25,"Load error before starting pulse"],
  [26,"Power Switch Array problem before starting pulse"],
  [27,"Tick count unexpectedly not zero when starting pulse"],
  [28,"Exceeded maximum Pod life of 80 hours Reported as \"Pod expired\""],
  [29,"Commissioned bit unexpectedly not set"],
  [30,"Unexpected commissioned state upon reset"],
  [31,"Alerts table corruption"],
  [32,"Validate encoder count error when bolusing"],
  [33,"Bad timer variable state"],
  [34,"Unexpected RTC Modulo Register value during reset"],
  [35,"Calibrate timer problem"],
  [37,"Tick interrupt handler unexpectedly called"],
  [39,"Failed to set up alerts for tank fill operation"],
  [40,"Bad arg or state"],
  [41,"Alert #0 auto-off timeout Auto-off"],
  [42,"Alert #1 auto-off timeout Not used"],
  [43,"Alert #2 auto-off timeout Not used"],
  [44,"Alert #3 auto-off timeout Not used"],
  [45,"Alert #4 auto-off timeout Not used"],
  [46,"Alert #5 auto-off timeout Not used"],
  [47,"Alert #6 auto-off timeout Not used"],
  [48,"Alert #7 auto-off timeout Not used"],
  [49,"Incorrect pod state for command"],
  [50,"Bad COP value during startup testing"],
  [51,"Multi Command Timeout Fault"],
  [52,"Reset from unknown cause More likely on third day of use due to low batteries and/or static electricity"],
  [53,"SAW Veto Status unexpectedly not set"],
  [54,"External pin reset with incorrect pod progress"],
  [55,"Bad beep pattern state variable"],
  [56,"Unexpected wire state"],
  [57,"Bad variable value for LOAD1/LOAD2 test"],
  [58,"Invalid value in message processing"],
  [59,"SAW reset testing failure"],
  [60,"MCP COP testing failure"],
  [61,"Problem with step sensor pump anchor"],
  [62,"Flash initialization or write error"],
  [64,"Encoder open count too high Probable pump issue"],
  [65,"Encoder count excessive variance"],
  [66,"Encoder count too low Safety check"],
  [67,"Encoder count problem"],
  [68,"Open load wire 1 detected Software or hardware failure in Pod"],
  [69,"Open load wire 2 detected Software or hardware failure in Pod"],
  [70,"Problem with Power Switch Array Status and Control Register values"],
  [71,"Problem with SAW VETO"],
  [72,"Bad timer calibration"],
  [73,"Bad timer high value"],
  [74,"Bad timer period value"],
  [75,"Bad ICS trim value"],
  [76,"Unable to trim ICS correctly"],
  [77,"Bad timer calibration mode"],
  [78,"SAW trim error Safety check"],
  [79,"Unexpected RF transmission error set during reset"],
  [80,"Timer Pulse-width Modulator 2 overflow Static electricity"],
  [81,"Bad state before starting pump"],
  [82,"Out of Lock Status Latch"],
  [83,"Wrong Rx sensitively value"],
  [84,"Packet frame length too long"],
  [85,"Unexpected IRQ high"],
  [86,"Unexpected IRQ low"],
  [87,"Pump check table corrupt"],
  [88,"Bad pump check table parameters"],
  [89,"Error updating pump check table"],
  [90,"Pump check table values too high"],
  [91,"Pump check table corruption"],
  [92,"Prime open count too low Problem with a safety check after priming"],
  [93,"Bad RF Carrier Detect Threshold"],
  [94,"Write flash byte to disable flash security failed"],
  [95,"Both wire 1 and wire 2 open before starting pump"],
  [96,"Timed pump check startup problem 1 Possible pump issue/occlusion"],
  [97,"Timed pump check startup problem 2 Possible pump issue/occlusion"],
  [98,"Timed pump check excess timeouts 1 Possible pump issue/occlusion"],
  [102,"Timed pump check excess timeouts 2 Possible pump issue/occlusion"],
  [103,"Timed pump check excess timeouts 3 Possible pump issue/occlusion"],
  [104,"Timed pump check pulse issue Possible pump issue/occlusion"],
  [105,"Timed pump check bolus problem Possible pump issue/occlusion"],
  [106,"Timed pump check above threshold Possible pump issue/occlusion"],
  [128,"Basal under infusion"],
  [129,"Basal over infusion"],
  [130,"Temp basal under infusion"],
  [131,"Temp basal over infusion"],
  [132,"Bolus under infusion"],
  [133,"Bolus over infusion"],
  [134,"Basal over infusion pulse"],
  [135,"Temp basal over infusion pulse"],
  [136,"Bolus over infusion pulse"],
  [137,"Immediate bolus under infusion pulse"],
  [138,"Extended bolus over infusion pulse"],
  [139,"Insulin schedule table corruption"],
  [141,"Bad pulse type parameter"],
  [142,"Sync request with no active temp basal"],
  [143,"Insulin command parse unexpectedly failed"],
  [144,"Bad Insulin Schedule Table selection parameter"],
  [145,"Basal pulse request with no active basal insulin schedule"],
  [146,"Temp basal pulse request with no active temp basal insulin schedule"],
  [147,"Bolus pulse request with with no active bolus insulin schedule"],
  [149,"Bad insulin command table specification"],
  [150,"Bolus termination with incorrect values"],
  [151,"Bad open transitions pod progress or count"]
];
const $ = id=>document.getElementById(id);
const hex = n=>'0x'+n.toString(16).toUpperCase().padStart(2,'0');
const units = u=>(Math.round(u*100)/100)+' U';
const time = iso=>new Date(iso).toLocaleTimeString([], {timeStyle:'short'});
const faultName = c=>{ const f=FAULTS.find(f=>f[0]===c); return f ? f[1] : 'unknown'; };
let last = {}, edited = {};

ALERTS.forEach((n,i)=>{ const l=document.createElement('label');
  l.innerHTML='<input type="checkbox" data-slot="'+i+'"> '+n+' ('+i+')'; $('alertChecks').appendChild(l); });
$('faultIn').innerHTML = FAULTS.map(f=>'<option value="'+f[0]+'">'+hex(f[0])+' — '+f[1].replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</option>').join('');
$('faultIn').value = 28;
['resIn','ageIn'].forEach(id=>$(id).oninput=()=>edited[id]=true);
$('alertChecks').onchange = ()=>edited.alerts=true;

function say(t){ $('msg').textContent=t; if(t) setTimeout(()=>{ if($('msg').textContent===t) $('msg').textContent=''; }, 4000); }

async function send(body, done){
  try {
    const r = await fetch('/command',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const t = await r.text();
    if(!r.ok) throw new Error(t.trim());
    show(JSON.parse(t)); say(done);
  } catch(e){ say('Failed — '+e.message); }
}

$('resSet').onclick = ()=>{ edited.resIn=false; send({command:'changeReservoir', value:+$('resIn').value}, 'Reservoir set'); };
$('ageSet').onclick = ()=>{ edited.ageIn=false; send({command:'setActiveTime', value:Math.round(+$('ageIn').value*60)}, 'Pod age set'); };
document.querySelectorAll('[data-hours]').forEach(b=>b.onclick=()=>{ edited.ageIn=false;
  send({command:'setActiveTime', value:Math.round(+b.dataset.hours*60)}, 'Pod age set to '+b.dataset.hours+' h'); });
$('alertsSet').onclick = ()=>{ let m=0; document.querySelectorAll('#alertChecks input').forEach(c=>{ if(c.checked) m|=1<<+c.dataset.slot; });
  edited.alerts=false; send({command:'setAlerts', value:m}, 'Alerts set'); };
$('faultSet').onclick = ()=>{ const c=+$('faultIn').value;
  if(confirm('Fault the pod with '+hex(c)+' — '+faultName(c)+'? A faulted pod stops delivery and must be replaced.'))
    send({command:'setFault', value:c}, 'Fault triggered'); };
$('faultClear').onclick = ()=>send({command:'setFault', value:0}, 'Fault cleared');
$('crashBefore').onclick = ()=>send({command:'crashNextCommand', beforeProcessing:true}, 'Armed');
$('crashAfter').onclick = ()=>send({command:'crashNextCommand', beforeProcessing:false}, 'Armed');

function chip(el, text, cls){ el.textContent=text; el.className='chip '+(cls||''); }

function show(s){
  last = s;
  document.title = s.modeName+' simulator';
  $('title').textContent = s.modeName+' pod';
  $('podid').textContent = s.id ? 'id '+s.id : (s.paired ? '' : 'not paired');
  $('controller').textContent = s.controllerId ? 'controller '+s.controllerId : '';
  $('sigRow').hidden = s.mode !== 'o5';
  $('badSigs').textContent = s.badSignatures;
  chip($('link'), s.connected ? 'connected' : 'not connected', s.connected ? 'ok' : '');
  $('reservoir').textContent = Math.round(s.reservoir*100)/100;
  const p = s.fault ? ['bad'] : s.progress>=8 && s.progress<=9 ? ['ok'] : ['warn'];
  chip($('progress'), s.progressName, p[0]);
  $('delivered').textContent = units(s.delivered);
  const h = Math.floor(s.minutesActive/60), m = s.minutesActive%60;
  $('age').textContent = s.paired ? h+' h '+m+' min of 80 h' : '—';
  $('basal').textContent = s.basalActive ? 'running' : 'not running';
  $('temp').textContent = s.tempBasalActive ? 'until '+time(s.tempBasalEnd) : 'none';
  $('bolus').textContent = s.bolusActive ? units(s.bolusRemaining)+' left' : 'none';
  const active = ALERTS.filter((n,i)=>s.alerts & (1<<i));
  $('alertsNow').textContent = active.length ? active.join(', ') : 'none';
  $('faultNow').textContent = s.fault ? hex(s.fault)+' — '+faultName(s.fault)+' (at '+s.faultMinutes+' min)' : 'none';
  if(!edited.resIn && document.activeElement!==$('resIn')) $('resIn').value = Math.round(s.reservoir*100)/100;
  if(!edited.ageIn && document.activeElement!==$('ageIn')) $('ageIn').value = Math.round(s.minutesActive/15)/4;
  if(!edited.alerts) document.querySelectorAll('#alertChecks input').forEach(c=>c.checked = !!(s.alerts & (1<<+c.dataset.slot)));
  $('crashNote').firstChild.textContent = s.crashNext
    ? 'Armed: the simulator exits '+s.crashNext+' processing the next command that changes delivery. '
    : 'The simulator exits at the next command that changes delivery, leaving the phone without a response. Restart it (run.sh does) to see how the app recovers.';
  $('msgSeq').textContent = s.msgSeq; $('cmdSeq').textContent = s.cmdSeq; $('nonceSeq').textContent = s.nonceSeq;
  $('eapSeq').textContent = s.eapAkaSeq; $('progSeq').textContent = s.lastProgSeqNum;
}

async function refresh(){ try { show(await (await fetch('/status')).json()); } catch(e){} }
refresh(); setInterval(refresh, 1000);
</script>
</body>
</html>`
