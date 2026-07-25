// official.js — one real, separate OS process per ceremony official.
//
// Each official runs distributed key generation (DKG): it picks its OWN secret,
// splits it, and sends an ENCRYPTED fragment to every other official. The
// coordinator only relays these ciphertexts — it cannot read them (they are
// RSA-encrypted to each recipient), so no single process ever learns the group
// secret. The group key only comes into being when >=threshold final shares are
// combined at T-0. This is the genuine "no dealer" property, running live.
//
// Launched by server.js via child_process.fork('official.js', [id]).
// Talks to the coordinator only through process IPC (send/on 'message').

const crypto = require('crypto');

const P = (1n << 256n) - 189n; // GF(p), same field as the coordinator
const randField = () => BigInt('0x' + crypto.randomBytes(40).toString('hex')) % P;

const id = Number(process.argv[2]);
let coeffs = [], threshold = 5, onlineIds = [], members = [], recv = {}, finalShare = null;

// vivid, terminal-style logging — this is what the browser terminal shows
const stamp = () => new Date().toISOString().slice(11, 19);
const log = (s) => console.log(`${stamp()}  ${s}`);

// each official mints its own ephemeral keypair; peers encrypt fragments to it
const kp = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const pubPem = kp.publicKey.export({ type: 'spki', format: 'pem' });

function f(x) { // evaluate this official's secret polynomial at x
  let y = 0n, xp = 1n;
  for (const c of coeffs) { y = (y + c * xp) % P; xp = (xp * x) % P; }
  return y;
}

process.send({ type: 'ready', id, pub: pubPem });
log(`● official #${id} booted — minted a private RSA keypair, awaiting ceremony`);

process.on('message', (msg) => {
  try {
    if (msg.type === 'config') {
      members = msg.members; onlineIds = msg.onlineIds; threshold = msg.threshold;
      if (!onlineIds.includes(id)) { log(`✗ this device is offline — sitting the ceremony out`); return; }
      // 1. pick my own secret sᵢ and a random degree-(t-1) polynomial
      coeffs = [randField()];
      for (let t = 1; t < threshold; t++) coeffs.push(randField());
      log(`◆ chose my private secret sᵢ + a degree-${threshold - 1} polynomial — nobody else will ever see sᵢ`);
      // 2. send an encrypted fragment f(j) to every active official j
      for (const j of onlineIds) {
        const y = f(BigInt(j)).toString(16).padStart(64, '0');
        const peer = members.find((m) => m.id === j);
        const enc = crypto.publicEncrypt(peer.pub, Buffer.from(y, 'hex')).toString('base64');
        process.send({ type: 'relay', from: id, to: j, enc });
      }
      log(`→ dispatched an encrypted fragment to each of the ${onlineIds.length} active officials`);
    }

    if (msg.type === 'share') { // a relayed ciphertext meant for me
      const y = crypto.privateDecrypt(kp.privateKey, Buffer.from(msg.enc, 'base64'));
      recv[msg.from] = BigInt('0x' + y.toString('hex'));
      log(`← received & decrypted a fragment from #${msg.from}  (${Object.keys(recv).length}/${onlineIds.length})`);
      if (Object.keys(recv).length === onlineIds.length) {
        // 3. my final share = sum of every fragment I received
        let sum = 0n;
        for (const k of onlineIds) sum = (sum + recv[k]) % P;
        finalShare = sum.toString(16).padStart(64, '0');
        const commitment = crypto.createHash('sha256').update(finalShare).digest('hex');
        log(`✓ summed all fragments → my final share is sealed. commitment ${commitment.slice(0, 12)}…`);
        process.send({ type: 'commitment', id, commitment });
      }
    }

    if (msg.type === 'release') {
      if (!onlineIds.includes(id) || !finalShare) return;
      log(`⚡ T-0 reached — releasing my final share to the coordinator`);
      process.send({ type: 'reveal', id, share: finalShare });
    }

    if (msg.type === 'shutdown') { log(`… powering down`); process.exit(0); }
  } catch (e) {
    log(`! error: ${e.message}`);
  }
});
