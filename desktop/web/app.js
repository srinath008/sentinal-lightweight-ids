'use strict';
const $=id=>document.getElementById(id);
const token=new URLSearchParams(location.hash.slice(1)).get('token');
if(token){sessionStorage.setItem('sentinel-token',token);history.replaceState(null,'',location.pathname);}
let state=null, actionError=null;
let dismissedAlert=null;
async function api(path,body){const r=await fetch('/api/'+path,{method:body?'POST':'GET',headers:{'X-Sentinel-Token':sessionStorage.getItem('sentinel-token')||'','Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});const data=await r.json();if(!r.ok)throw Error(data.error||'Request failed');return data;}
let noticeTimer=null, reportFolderShown=false, dismissedError=null;
function notice(text,transient){
  const shown=text&&text!==dismissedError;
  $('notice-text').textContent=shown?text:'';$('notice').hidden=!shown;
  $('open-reports').hidden=!(shown&&reportFolderShown);
  if(transient&&text){clearTimeout(noticeTimer);noticeTimer=setTimeout(()=>{actionError=null;reportFolderShown=false;notice(null);},25000);}
}
$('notice-close').addEventListener('click',()=>{dismissedError=state&&state.error?state.error:null;actionError=null;reportFolderShown=false;notice(null);});
async function openReports(){try{const r=await api('open-reports',{});if(!r.opened){actionError='Reports are in '+r.folder;notice(actionError,true);}}catch(e){actionError=e.message;notice(actionError,true);}}
$('open-reports').addEventListener('click',openReports);$('open-reports-main').addEventListener('click',openReports);
let lastAlertId=null, titleTimer=null;
function soundAlert(){try{const c=new (window.AudioContext||window.webkitAudioContext)();[880,660,880].forEach((f,i)=>{const o=c.createOscillator(),g=c.createGain();o.frequency.value=f;g.gain.value=.15;o.connect(g);g.connect(c.destination);o.start(c.currentTime+i*.22);o.stop(c.currentTime+i*.22+.16);});}catch(_){}}
function flashTitle(text){clearInterval(titleTimer);const base='Sentinel · Behavioral Detection';let on=false,n=0;titleTimer=setInterval(()=>{document.title=(on=!on)?'⚠ '+text:base;if(++n>20){clearInterval(titleTimer);document.title=base;}},700);}
function renderModel(){
  const info=state.model_info||{}, m=info.historical_metrics;
  $('model-label').textContent=info.display_name||state.model||'Behavioral model';
  $('model-scope').textContent=info.experimental_host_adaptation?'This device · experimental preview':'Historical model · schema 2';
  $('model-recall').textContent=m?(100*m.recall).toFixed(2)+'%':'—';
  $('model-fpr').textContent=m?(100*m.baseline_false_positive_rate).toFixed(2)+'%':'—';
  $('model-f1').textContent=m?m.f1.toFixed(3):'—';
  $('model-recall-count').textContent=m?m.true_positives+' / '+(m.true_positives+m.false_negatives)+' historical simulated attack windows':'No historical evaluation available';
  $('model-fpr-count').textContent=m?m.false_positives+' / '+(m.false_positives+m.true_negatives)+' historical normal windows':'No historical evaluation available';
  const local=info.local_evaluation, note=$('model-local-note');
  note.hidden=!local;
  if(local){const normal=['idle','benign'].map(k=>local[k]).filter(Boolean);
    note.textContent='Local preview checks: '+normal.reduce((n,x)=>n+x.flagged,0)+' / '+normal.reduce((n,x)=>n+x.windows,0)+' normal activity windows flagged. These short checks on this device do not establish general malware accuracy.';}
}
function show(view){document.querySelectorAll('.view').forEach(e=>e.hidden=e.id!==view);document.querySelectorAll('.nav').forEach(e=>e.classList.toggle('active',e.dataset.view===view));$('breadcrumb').textContent={overview:'Overview',history:'Incident history',system:'System checks',model:'About the model'}[view];if(view==='history')loadHistory();}
document.querySelectorAll('[data-view]').forEach(e=>e.addEventListener('click',()=>show(e.dataset.view)));
document.querySelector('.brand').addEventListener('click',e=>{e.preventDefault();show('overview');});
function liveReady(){return !!state && state.checks.every(c=>c.ok);}
function updateControls(){
  const live=$('mode').value==='live';
  $('speed-label').hidden=live;
  $('start').textContent=live?(liveReady()?'▶ Start monitoring':'View system checks ↗'):'▶ Start replay';
  $('mode-help').textContent=live?(liveReady()?'Monitors Linux activity only. Authorization will be requested when you start.':'Live monitoring needs setup. Open System checks to see what is missing.'):'Replay uses recorded activity; it does not monitor your current system.';
  $('mode-help').classList.toggle('setup-required',live&&!liveReady());
  if(state)$('status').dataset.status=state.status;
}
function evidenceText(e){
  if(!e.explanation)return e.message||'';
  const x=e.explanation, parts=[x.summary,x.observations.join(' · ')];
  if(x.context.exec_commands?.length)parts.push('Commands started: '+x.context.exec_commands.map(c=>c.name+' ×'+c.count).join(', '));
  if(x.context.processes?.length)parts.push('Observed processes: '+x.context.processes.map(p=>p.name+' (PID '+p.pid+', '+p.observed_events+' '+p.source+' events)').join('; '));
  if(x.context.sample_paths?.length)parts.push('Sample file paths: '+x.context.sample_paths.join('; '));
  if(x.context.sample_destinations?.length)parts.push('Sample destinations: '+x.context.sample_destinations.join('; '));
  parts.push(x.limitation);
  return parts.join('\n');
}
function renderAlerts(events){
  const e=events.find(e=>(e.type==='incident_start'&&e.notification)||e.type==='test_alert'||(e.type==='file_scan_result'&&e.scan?.detections.length));
  $('security-alert').hidden=!e||e.event_id===dismissedAlert;
  if(!e)return;
  if(e.event_id!==lastAlertId){const fresh=lastAlertId!==null||e.recorded_at>Date.now()/1000-30;lastAlertId=e.event_id;if(fresh&&e.event_id!==dismissedAlert&&e.mode!=='replay'){soundAlert();flashTitle(e.type==='test_alert'?'Test alert':'Unusual activity detected');}}
  $('alert-title').textContent=e.type==='test_alert'?'Test alert · no threat detected':e.type==='file_scan_result'?'File scan detections need review':e.mode==='replay'?'Recorded replay · unusual activity':'Unusual Linux activity detected';
  $('alert-detail').textContent=e.type==='incident_start'?'Two consecutive windows differed from the model’s learned normal behavior.':e.message;
  $('alert-evidence').textContent=e.type==='file_scan_result'?e.scan.detections.map(d=>d.signature+' · '+d.path).join('\n'):evidenceText(e);
  $('dismiss-alert').onclick=()=>{dismissedAlert=e.event_id;$('security-alert').hidden=true;};
}
async function renderProtection(){
  const p=await api('protection'),s=p.scanner;
  $('notification-status').textContent=(p.notifications.detail||'In-app alerts active.')+(p.app_memory_mib?' · Main-process memory: '+p.app_memory_mib+' MiB (WebKit/scanner additional)':'');
  const ready=s.engine.ready;
  $('scan-start').disabled=!ready||s.status==='running';
  $('scan-stop').disabled=s.status!=='running';
  $('scanner-status').textContent=!ready?'File scanning unavailable: install ClamAV and update official signatures.':'ClamAV ready · '+(s.engine.signature_updated?'signatures downloaded '+new Date(s.engine.signature_updated*1000).toLocaleString()+' · ':'')+s.status+' · '+s.scanned+' files scanned · '+(s.detection_count??s.detections.length)+' detections · '+s.skipped+' skipped'+((s.detection_count??0)>s.detections.length?' · showing first '+s.detections.length+' detections (see ClamAV for full details)':'')+(s.limit_reached?' · scan limit reached':'')+(s.peak_memory_mib?' · scan peak: '+s.peak_memory_mib+' MiB':'')+(s.error?' · '+s.error:'');
  $('scan-results').replaceChildren();
  s.detections.forEach(d=>{const row=document.createElement('div');row.className='scan-detection';row.textContent=d.kind+': '+d.signature+'\n'+d.path;$('scan-results').append(row);});
}
$('test-alert').addEventListener('click',async()=>{const b=$('test-alert');b.disabled=true;try{await api('test-alert',{});}catch(e){actionError=e.message;notice(actionError);}finally{b.disabled=false;}});
$('scan-start').addEventListener('click',async()=>{try{await api('scan',{path:$('scan-path').value});actionError=null;notice(null);}catch(e){actionError=e.message;notice(actionError);}});
$('scan-stop').addEventListener('click',async()=>{try{await api('scan-stop',{});}catch(e){actionError=e.message;notice(actionError);}});
function eventList(el,events){el.replaceChildren();if(!events.length){const p=document.createElement('p');p.className='empty';p.textContent='No recorded events yet.';el.append(p);return;}events.forEach(e=>{const row=document.createElement('div');row.className='event-row';const icon=document.createElement('span');icon.className='event-icon'+(['incident_start','error','collector_stderr'].includes(e.type)?' warning':'');icon.textContent=e.type==='incident_start'?'△':'⌁';const detail=document.createElement('div'),p=document.createElement('p'),small=document.createElement('small'),tag=document.createElement('span');p.textContent={incident_start:e.notification?'Unusual activity · incident started':'Unusual activity · incident grouped (notification cooldown)',incident_end:'Activity returned to normal',monitor_started:'Live collector started',monitor_stopped:'Live collector stopped',replay_boundary:'Recording segment changed',collector_stderr:'Collector health message',error:'Session error',test_alert:'Test alert · no threat detected',file_scan_result:'ClamAV file scan result'}[e.type]||e.type;small.textContent=e.explanation?evidenceText(e):e.message|| (e.window_start?new Date(e.window_start*1000).toLocaleString():e.created?new Date(e.created*1000).toLocaleString():'Monitoring event');detail.append(p,small);tag.className='tag';tag.textContent={replay:'REPLAY',live:'LIVE',demo:'TEST',file_scan:'FILE SCAN'}[e.mode]||'EVENT';row.append(icon,detail,tag);el.append(row);});}
function chart(windows){$('chart').toggleAttribute('hidden',!windows.length);$('chart-empty').hidden=!!windows.length;if(!windows.length)return;const scores=windows.map(w=>Object.values(w.scores)[0]),min=Math.min(...scores),max=Math.max(...scores),range=max-min||1;const coords=scores.map((s,i)=>[10+i*780/Math.max(1,scores.length-1),180-(s-min)*155/range]);const svg=$('chart');svg.replaceChildren();const node=(name,attrs)=>{const e=document.createElementNS('http://www.w3.org/2000/svg',name);Object.entries(attrs).forEach(([k,v])=>e.setAttribute(k,v));svg.append(e);return e;};[25,75,125,180].forEach(y=>node('line',{x1:0,y1:y,x2:800,y2:y,stroke:'#29352c','stroke-width':1}));node('polyline',{points:coords.map(p=>p.join(',')).join(' '),fill:'none',stroke:'#b9f568','stroke-width':2});windows.forEach((w,i)=>{if(w.anomaly)node('circle',{cx:coords[i][0],cy:coords[i][1],r:3,fill:'#ffb56b'});});}
async function poll(){try{state=await api('state');renderModel();renderAlerts(state.events);await renderProtection();updateControls();notice(state.error||actionError);$('status').textContent='● '+state.status;const running=['running','starting'].includes(state.status);$('start').disabled=running;$('stop').disabled=!running;$('mode').disabled=running;$('speed').disabled=running;['total','flagged','incidents'].forEach(k=>$(k).textContent=state[k].toLocaleString());$('monitor-title').textContent=running?(state.mode==='replay'?'Replaying a recorded session.':'Watching Linux activity.'):(state.status==='completed'?(state.mode==='replay'?'Recorded replay complete.':'Live monitoring complete.'):state.status==='error'?'Monitoring needs attention.':'Ready when you are.');$('monitor-detail').textContent=state.mode==='replay'?'Historical feature windows · scored with the current model · no live activity is being monitored.':running?'Linux activity only · flagged behavior requires human review.':'Replay a recorded session, or check your system to start live monitoring.';chart(state.windows);renderFeed();$('chart-source').textContent=state.mode==='replay'?'RECORDED REPLAY':state.mode==='live'?'LIVE LINUX':'NO SESSION';const w=state.windows.at(-1);if(w){$('exec').textContent=w.n_exec;$('open').textContent=w.n_open_raw??Math.round(Math.expm1(w.n_open));$('tcp').textContent=w.n_tcp_connect;$('errors').textContent=w.n_open_errors;$('phase').textContent=state.mode==='replay'?'Recorded label: '+w.phase.replaceAll('_',' ')+' · '+w.session_id:'Current Linux window · '+new Date(w.window_start*1000).toLocaleTimeString();}else{['exec','open','tcp','errors'].forEach(k=>$(k).textContent='—');$('phase').textContent='Waiting for a complete activity window.';}eventList($('events'),state.events.slice(0,8));$('checks').replaceChildren();state.checks.forEach(c=>{const row=document.createElement('div');row.className='check'+(c.ok?'':' fail');const b=document.createElement('b');b.textContent=c.ok?'✓':'!';const d=document.createElement('div'),p=document.createElement('p'),small=document.createElement('small');p.textContent=c.name;small.textContent=c.detail;d.append(p,small);row.append(b,d);$('checks').append(row);});}catch(e){notice('Connection unavailable: '+e.message);}finally{setTimeout(poll,900);}}
$('mode').addEventListener('change',updateControls);
$('start').addEventListener('click',async()=>{if($('mode').value==='live'&&!liveReady()){show('system');return;}try{await api('start',{mode:$('mode').value,speed:$('speed').value});actionError=null;notice(null);}catch(e){actionError=e.message;notice(actionError);}});
$('stop').addEventListener('click',async()=>{try{await api('stop',{});}catch(e){actionError=e.message;notice(actionError);}});
async function loadHistory(){try{eventList($('history-list'),await api('history'));}catch(e){actionError=e.message;notice(actionError);}}
$('refresh-history').addEventListener('click',loadHistory);
$('export').addEventListener('click',async()=>{const b=$('export');b.disabled=true;try{const report=await api('export',{});reportFolderShown=true;actionError=report.message+'\n'+(report.windows_files&&report.windows_files.length?report.windows_files:report.saved_files).join('\n');notice(actionError,true);}catch(e){actionError=e.message;notice(actionError);}finally{b.disabled=false;}});
function feedRow(w,live){
  const row=document.createElement('div');row.className='feed-row'+(w.anomaly?' flagged':'');
  const t=document.createElement('span');t.className='feed-time';t.textContent=new Date(w.window_start*1000).toLocaleTimeString();
  const body=document.createElement('div');body.className='feed-body';
  const main=document.createElement('div');main.className='feed-main';
  const open=w.n_open_raw??Math.round(Math.expm1(w.n_open));
  main.textContent='exec '+w.n_exec+' · opens '+open.toLocaleString()+' · errors '+w.n_open_errors+' · tcp '+w.n_tcp_connect+' · score '+Object.values(w.scores)[0].toFixed(2);
  body.append(main);
  if(w.anomaly){const ev=document.createElement('small');ev.className='feed-evidence';const x=w.evidence||{},lines=[];
    if(x.exec_commands?.length)lines.push('Commands started: '+x.exec_commands.map(c=>c.name+' ×'+c.count).join(', '));
    if(x.processes?.length)lines.push('Busiest processes: '+x.processes.map(p=>p.name+' (PID '+p.pid+', '+p.observed_events+')').join(', '));
    if(x.sample_paths?.length)lines.push('Files: '+x.sample_paths.slice(0,3).join('; '));
    if(x.sample_destinations?.length)lines.push('Connections: '+x.sample_destinations.slice(0,3).join('; '));
    if(!live)lines.push('Recorded label: '+w.phase.replaceAll('_',' ')+' (no process/path attribution in replay)');
    ev.textContent=lines.join('\n')||'No process detail captured for this window.';body.append(ev);}
  const tag=document.createElement('span');tag.className='feed-tag';tag.textContent=w.anomaly?'FLAGGED':'normal';
  row.append(t,body,tag);return row;
}
function renderFeed(){
  const feed=$('feed'),ws=state.windows.slice(-40).reverse(),live=state.mode==='live';
  if(!ws.length){feed.replaceChildren();const p=document.createElement('p');p.className='empty';p.textContent='Windows appear here as each 5-second window completes.';feed.append(p);$('feed-heartbeat').textContent='Waiting for the first complete window.';return;}
  feed.replaceChildren(...ws.map(w=>feedRow(w,live)));
  const age=Math.max(0,Math.round(Date.now()/1000-ws[0].recorded_at)),running=['running','starting'].includes(state.status);
  const lastIncident=state.events.find(e=>e.type==='incident_start'||e.type==='incident_end'),flaggedNow=ws[0].anomaly&&!(lastIncident&&lastIncident.type==='incident_start');
  $('feed-heartbeat').textContent=(running?(live?'Live · last window completed '+age+' s ago. Windows complete every 5 s.':'Replaying recorded windows.'):'Session '+state.status+'.')+(running&&flaggedNow?' Early warning: latest window flagged; an incident is raised if the next window is also flagged.':'');
  $('feed-heartbeat').classList.toggle('early-warning',running&&flaggedNow);
}
poll();
