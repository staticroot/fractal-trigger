{ pkgs, module, package }:

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
      mode = "standalone";
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

    # 1. Agent switch repoints the system profile at the target.
    machine.succeed(call("SwitchToStorePath", f'sss {target} "" ""'))
    profile = machine.succeed("readlink -f /nix/var/nix/profiles/system").strip()
    assert profile == target, f"profile {profile} != target {target}"

    # 2. A non-agent caller is refused by the D-Bus policy.
    machine.fail(call("LockScreen", "", user="nobody"))

    # 3. LockScreen succeeds for the agent.
    machine.succeed(call("LockScreen", ""))
  '';
}
