// Security-themed 3D scenes (dependency-free canvas 3D). Each page selects a scene: BG.set("lock"|"vault"|"radar"|"shield"|"tunnel")
const BG=(()=>{const c=document.getElementById("bg"),x=c.getContext("2d"),RM=matchMedia("(prefers-reduced-motion: reduce)").matches;
let W,H,ac="#22d3ee",ac2="#6366f1",mx=0,my=0,t=0,n=0,cur="vault",tgt="vault",fade=1;
const rs=()=>{W=c.width=innerWidth;H=c.height=innerHeight};rs();addEventListener("resize",rs);addEventListener("mousemove",e=>{mx=e.clientX/W-.5;my=e.clientY/H-.5});
const rot=([X,Y,Z],a,b)=>{let c1=Math.cos(a),s1=Math.sin(a),q=X*c1+Z*s1;Z=-X*s1+Z*c1;X=q;let c2=Math.cos(b),s2=Math.sin(b);q=Y*c2-Z*s2;Z=Y*s2+Z*c2;return[X,q,Z]};
const P=p=>{const f=800/(800+p[2]+500);return[W*(innerWidth>900?.62:.5)+p[0]*f,H*.5+p[1]*f,f]};
const col=()=>{const s=getComputedStyle(document.documentElement);ac=s.getPropertyValue("--ac").trim();ac2=s.getPropertyValue("--ac2").trim()};
const ga=a=>x.globalAlpha=a*fade,V=(w,h,d,oy=0)=>{const v=[];for(const a of[-1,1])for(const b of[-1,1])for(const e of[-1,1])v.push([a*w,b*h+oy,e*d]);return v};
const E=[[0,1],[2,3],[4,5],[6,7],[0,2],[1,3],[4,6],[5,7],[0,4],[1,5],[2,6],[3,7]];
const box=(w,h,d,oy,A,B,al=.9)=>{const v=V(w,h,d,oy).map(p=>P(rot(p,A,B)));x.strokeStyle=ac;ga(al);x.beginPath();E.forEach(([i,j])=>{x.moveTo(v[i][0],v[i][1]);x.lineTo(v[j][0],v[j][1])});x.stroke()};
const path=(pts,A,B,close)=>{x.beginPath();pts.forEach((p,i)=>{const q=P(rot(p,A,B));i?x.lineTo(q[0],q[1]):x.moveTo(q[0],q[1])});if(close)x.closePath();x.stroke()};
const dot=(p,r,A,B,fill)=>{const q=P(rot(p,A,B));x.fillStyle=fill;x.beginPath();x.arc(q[0],q[1],Math.max(.5,r*q[2]*1.6),0,6.283);x.fill();return q};
const sph=(N,r0,r1,ys=1)=>Array.from({length:N},()=>{const r=r0+Math.random()*(r1-r0),u=Math.random()*2-1,a=Math.random()*6.283,s=Math.sqrt(1-u*u);return{p:[r*s*Math.cos(a),r*u*ys,r*s*Math.sin(a)],w:(Math.random()*.5+.15)*(Math.random()<.5?-1:1),pulse:0,v:Math.random()<.22}});
const S={
 lock(A,B){ // padlock: authentication gate with orbiting key particles
  x.lineWidth=1.6;box(110,80,45,70,A,B);x.strokeStyle=ac;ga(.9);for(const z of[-30,30])path(Array.from({length:21},(_,i)=>{const a=i/20*Math.PI;return[60*Math.cos(a),-10-80*Math.sin(a),z]}),A,B);
  path([[-60,-10,-30],[-60,-10,30]],A,B);path([[60,-10,-30],[60,-10,30]],A,B);x.strokeStyle=ac2;ga(.9);path(Array.from({length:17},(_,i)=>{const a=i/16*6.283;return[Math.cos(a)*15,62+Math.sin(a)*15,-45]}),A,B,1);path([[0,72,-45],[0,100,-45]],A,B);
  const k=S._k||(S._k=Array.from({length:70},(_,i)=>({a:i/70*6.283,r:230+Math.random()*120,y:(Math.random()-.5)*160})));k.forEach((q,i)=>{const a=q.a+t*.7,hit=((t*1.2-a)%6.283+6.283)%6.283<.2;ga(hit?1:.5);dot([Math.cos(a)*q.r,q.y,Math.sin(a)*q.r],hit?4:2,A,B,hit?ac2:ac)})},
 vault(A,B){ // data vault with scanning ring; packets flash when scanned
  x.lineWidth=1.5;box(130,130,130,0,A,B);box(80,80,80,0,A,B,.5);const sy=Math.sin(t*1.3)*230;x.strokeStyle=ac2;x.lineWidth=2;ga(.6);path(Array.from({length:65},(_,i)=>{const a=i/64*6.283;return[Math.cos(a)*420,sy,Math.sin(a)*420]}),A,B);
  const k=S._p||(S._p=sph(200,260,580,.6));k.forEach(q=>{const o=rot(q.p,t*q.w,0),hit=Math.abs(o[1]-sy)<28;ga(hit?1:.5);dot(o,hit?4:1.6,A,B,hit?ac2:ac)})},
 radar(A,B){ // network graph + radar sweep: swept hosts ping, vulnerable hosts glow
  const k=S._n||(S._n=(()=>{const a=sph(46,180,440,.7),e=[];a.forEach((p,i)=>a.forEach((q,j)=>{if(j>i&&Math.hypot(...p.p.map((v,m)=>v-q.p[m]))<190)e.push([i,j])}));return{a,e}})()),sw=(t*1.4)%6.283,pts=k.a.map(o=>P(rot(o.p,A,B)));
  x.strokeStyle=ac;x.lineWidth=1;ga(.22);x.beginPath();k.e.forEach(([i,j])=>{x.moveTo(pts[i][0],pts[i][1]);x.lineTo(pts[j][0],pts[j][1])});x.stroke();ga(.3);for(const r of[150,300,460])path(Array.from({length:65},(_,i)=>{const a=i/64*6.283;return[Math.cos(a)*r,0,Math.sin(a)*r]}),A,B);
  const c0=P(rot([0,0,0],A,B));x.fillStyle=ac;ga(.12);x.beginPath();x.moveTo(c0[0],c0[1]);for(let i=0;i<=12;i++){const a=sw-.6+i*.05,q=P(rot([Math.cos(a)*460,0,Math.sin(a)*460],A,B));x.lineTo(q[0],q[1])}x.fill();x.strokeStyle=ac2;x.lineWidth=2;ga(.8);path([[0,0,0],[Math.cos(sw)*460,0,Math.sin(sw)*460]],A,B);
  k.a.forEach((o,i)=>{const az=(Math.atan2(o.p[2],o.p[0])+6.283)%6.283;if(((sw-az)+6.283)%6.283<.12)o.pulse=1;o.pulse*=.97;const q=pts[i],r=(3+o.pulse*8)*q[2]*1.8;ga(Math.min(1,.5*q[2]+.3));x.fillStyle=o.v?ac2:ac;x.beginPath();x.arc(q[0],q[1],r,0,6.283);x.fill();if(o.v){x.strokeStyle=ac2;x.lineWidth=1.2;ga(.5);x.beginPath();x.arc(q[0],q[1],r+5+Math.sin(t*4+i)*2,0,6.283);x.stroke()}})},
 shield(A,B){ // policy shield: threats approach and are blocked/scanned
  const sh=[[0,-150],[110,-110],[110,10],[0,150],[-110,10],[-110,-110]];x.lineWidth=1.8;x.strokeStyle=ac;ga(.9);for(const z of[-25,25])path(sh.map(p=>[p[0],p[1],z]),A,B,1);sh.forEach(p=>path([[p[0],p[1],-25],[p[0],p[1],25]],A,B));
  x.strokeStyle=ac2;ga(.95);x.lineWidth=2.4;path([[-45,0,27],[-10,40,27],[55,-40,27]],A,B);const sy=Math.sin(t*1.5)*130;x.lineWidth=1.5;ga(.7);path([[-170,sy,-25],[170,sy,-25],[170,sy,25],[-170,sy,25]],A,B,1);
  const k=S._t||(S._t=Array.from({length:46},()=>({y:(Math.random()-.5)*340,z:(Math.random()-.5)*240,s:(Math.random()<.5?-1:1),sp:.15+Math.random()*.2,o:Math.random()})));k.forEach(q=>{const u=(t*q.sp+q.o)%1,xx=q.s*(560-u*430),near=u>.92;ga(near?1:.55);dot([xx,q.y,q.z],near?5:2,A,B,near?ac2:ac)})},
 tunnel(A,B){ // firewall tunnel: inspection rings streaming toward the viewer
  x.lineWidth=1.3;for(let i=0;i<16;i++){const z=((i*90+t*160)%1440)-300,s=240;ga(Math.max(.1,.8-z/1400));x.strokeStyle=i%5==0?ac2:ac;path([[-s,-s,z],[s,-s,z],[s,s,z],[-s,s,z]],A*.3,B*.3,1)}
  ga(.35);x.strokeStyle=ac;for(const[a,b]of[[-1,-1],[1,-1],[1,1],[-1,1]])path([[a*240,b*240,-300],[a*240,b*240,1140]],A*.3,B*.3);
  const k=S._d||(S._d=Array.from({length:60},()=>({x:(Math.random()-.5)*440,y:(Math.random()-.5)*440,o:Math.random(),v:Math.random()<.15})));k.forEach(q=>{const z=((q.o*1440+t*260)%1440)-300;ga(.9);dot([q.x,q.y,z],q.v?5:2.2,A*.3,B*.3,q.v?ac2:ac)})}
};
function f(){if(!document.hidden){if(!RM)t+=.008;if(!(n++%30))col();if(cur!==tgt){fade-=.1;if(fade<=0){cur=tgt;fade=0}}else if(fade<1)fade=Math.min(1,fade+.06);x.clearRect(0,0,W,H);S[cur](t*.35+mx*1.1,.4+my*.5);x.globalAlpha=1}requestAnimationFrame(f)}
col();f();return{set:s=>{if(S[s])tgt=s}}})();
