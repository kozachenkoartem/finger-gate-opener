import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';

const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const elements = new Map();
const element = id => {
    if (!elements.has(id)) elements.set(id, {hidden:false, disabled:false, textContent:'', value:'', querySelector:()=>({disabled:false})});
    return elements.get(id);
};
let status = {
    state:'connected', message:'Previous Wi-Fi remains connected', ssid:'old', sta_ip:'10.0.0.2',
    ap_active:false, ap_ip:'', hostname:'finger-gate-test', last_trial:'',
    network_command:{id:7,result:'busy'},
};
const context = vm.createContext({
    document:{getElementById:element}, setTimeout:()=>1, clearTimeout:()=>{},
    fetch:async path=>({ok:path!=='/api/session', status:path==='/api/session'?401:200,
        json:async()=>path==='/api/session'?{error:'Sign in'}:path==='/api/hub/token'?{token:'new-token-once'}:status}),
    console,
});
vm.runInContext(script, context);
await new Promise(resolve=>setImmediate(resolve));
element('message').textContent = 'New Wi-Fi trial queued';
await vm.runInContext('pendingWifiCommand=7; refresh()', context);
assert.match(element('message').textContent, /not started.*busy/i,
    'Owner rejection after HTTP 202 must not leave the UI claiming a queued trial');

status = {...status, network_command:{id:8,result:'queued'}};
element('message').textContent = 'Waiting for network task';
await vm.runInContext('pendingWifiCommand=8; refresh()', context);
assert.equal(element('message').textContent, 'Waiting for network task', 'A queued receipt is not terminal success or failure');
console.log('Network command UI admission/rejection: PASS');

await vm.runInContext("issueHubToken('create')", context);
assert.equal(element('hubToken').value, 'new-token-once', 'only an explicit create action displays the newly issued token');
await vm.runInContext('showLogin()', context);
assert.equal(element('hubToken').value, '', 'a previously issued token is removed rather than rendered in a later session');
console.log('Hub token one-time display: PASS');
