{ config, lib, pkgs, ... }:

let
  cfg = config.services.fractal-trigger;

  busName = "systems.staticroot.Trigger";

  dbusPolicy = pkgs.runCommand "fractal-trigger-dbus-policy" {
    policy = pkgs.replaceVars ./dbus-policy.conf { inherit (cfg) agentUser; };
  } ''
    install -Dm0644 "$policy" "$out/share/dbus-1/system.d/${busName}.conf"
  '';
in
{
  options.services.fractal-trigger = {
    enable = lib.mkEnableOption "the fractal-trigger privileged executor";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.fractal-trigger;
      defaultText = lib.literalExpression "pkgs.fractal-trigger";
      description = "The fractal-trigger package to run.";
    };

    agentUser = lib.mkOption {
      type = lib.types.str;
      description = "Unix user of fractal-agent, the only caller allowed to reach the trigger.";
    };

    trustedKeysFile = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/fractal-trigger/trusted-keys";
      description = ''
        Root-owned, root-only-writable file of trusted Ed25519 public keys, one
        hex-encoded 32-byte key per line. This file is the real root of trust:
        whoever can write it controls what the trigger will activate. In
        standalone mode fractal-agent's provisioning writes the local public key
        here; a managed device would carry only the control-plane key.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.dbus.packages = [ dbusPolicy ];

    systemd.services.fractal-trigger = {
      description = "Fractal Linux privileged trigger";
      wantedBy = [ "multi-user.target" ];
      after = [ "dbus.service" ];
      requires = [ "dbus.service" ];

      path = [ pkgs.lix ];

      # Deliberately unsandboxed: switch-to-configuration needs full root access
      # (writes /boot and /etc, restarts units, runs activation scripts).
      serviceConfig = {
        Type = "dbus";
        BusName = busName;
        ExecStart = "${cfg.package}/bin/fractal-trigger";
        User = "root";
        Restart = "on-failure";
        StateDirectory = "fractal-trigger";
        Environment = "FRACTAL_TRIGGER_TRUSTED_KEYS=${cfg.trustedKeysFile}";
      };
    };
  };
}
