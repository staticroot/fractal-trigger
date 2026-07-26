{ pkgs, module, package }:

let
  py = pkgs.python3.withPackages (ps: [ ps.cryptography ]);

  # Test-only provisioning: mint a standalone Ed25519 keypair, publish the public
  # key into the trigger's trusted-keys file, and keep the seed for signing.
  keygen = pkgs.writeScript "fractal-test-keygen" ''
    #!${py}/bin/python3
    import os
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.generate()
    seed = sk.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    pub = sk.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)

    with open("/root/signing-seed", "w") as f:
        f.write(seed.hex())
    os.chmod("/root/signing-seed", 0o600)

    os.makedirs("/var/lib/fractal-trigger", exist_ok=True)
    with open("/var/lib/fractal-trigger/trusted-keys", "w") as f:
        f.write(pub.hex() + "\n")
  '';

  # Sign like the real signer (activation) or the managed control plane (lock):
  # the exact domain-separated, length-prefixed encoding the trigger verifies.
  #   sign activation <store> <nonce>   |   sign lock <nonce>
  # Prints the signature as hex.
  sign = pkgs.writeScript "fractal-test-sign" ''
    #!${py}/bin/python3
    import struct, sys
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    def lp(s):
        return struct.pack("<Q", len(s)) + s.encode()

    op = sys.argv[1]
    if op == "activation":
        store, nonce = sys.argv[2], sys.argv[3]
        msg = b"systems.staticroot.trigger/activation/v1" + lp(store) + lp(nonce)
    elif op == "lock":
        nonce = sys.argv[2]
        msg = b"systems.staticroot.trigger/lock/v1" + lp(nonce)
    else:
        sys.exit(f"unknown op {op}")

    seed = bytes.fromhex(open("/root/signing-seed").read().strip())
    sys.stdout.write(Ed25519PrivateKey.from_private_bytes(seed).sign(msg).hex())
  '';
in
pkgs.testers.runNixOSTest {
  name = "fractal-trigger";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ module ];

    users.users.agent = {
      isNormalUser = true;
      uid = 1001;
    };

    system.switch.enable = true;

    services.fractal-trigger = {
      enable = true;
      inherit package;
      agentUser = "agent";
    };

    systemd.services.fractal-trigger-provision = {
      description = "Provision the test standalone signing keypair";
      wantedBy = [ "multi-user.target" ];
      before = [ "fractal-trigger.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = keygen;
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("fractal-trigger.service")

    # Use the VM's own system closure as the target: re-activating it exercises
    # the full switch path while staying idempotent (won't break the live VM).
    target = machine.succeed("readlink -f /run/current-system").strip()

    def call(method, args, user="agent"):
        return (
            f"sudo -u {user} busctl --quiet --timeout=120 call systems.staticroot.Trigger "
            f"/systems/staticroot/Trigger systems.staticroot.Trigger {method} {args}"
        )

    def issue_nonce():
        # busctl prints: s "<nonce>"
        return machine.succeed(call("IssueNonce", "")).strip().split('"')[1]

    def sign(op, *args):
        return machine.succeed(f"${sign} {op} {' '.join(args)}").strip()

    # 1. Happy path: issue → sign → switch repoints the system profile.
    nonce = issue_nonce()
    sig = sign("activation", target, nonce)
    machine.succeed(call("SwitchToStorePath", f"sss {target} {sig} {nonce}"))
    profile = machine.succeed("readlink -f /nix/var/nix/profiles/system").strip()
    assert profile == target, f"profile {profile} != target {target}"

    # 2. Replay: the burned nonce is no longer pending, so the same pair fails.
    machine.fail(call("SwitchToStorePath", f"sss {target} {sig} {nonce}"))

    # 3. Unsigned activation is refused even with a fresh nonce.
    fresh = issue_nonce()
    machine.fail(call("SwitchToStorePath", f'sss {target} "" {fresh}'))

    # 4. A non-agent caller is refused by the D-Bus policy before authority even matters.
    machine.fail(call("LockScreen", 'ss "" ""', user="nobody"))

    # 5. Unsigned lock is refused: the caller policy is reachability, not authority.
    fresh = issue_nonce()
    machine.fail(call("LockScreen", f'ss "" {fresh}'))

    # 6. An activation signature must not authorize a lock on the same nonce.
    cross = sign("activation", target, fresh)
    machine.fail(call("LockScreen", f"ss {cross} {fresh}"))

    # 7. A properly signed lock succeeds (the nonce above survived the rejections).
    locksig = sign("lock", fresh)
    machine.succeed(call("LockScreen", f"ss {locksig} {fresh}"))
  '';
}
