{ config, lib, pkgs, ... }:

let
  cfg = config.services.fractal-trigger;

  busName = "systems.staticroot.Trigger";

  dbusPolicy = pkgs.runCommand "fractal-trigger-dbus-policy" {
    policy = pkgs.replaceVars ./dbus-policy.conf { inherit (cfg) agentUser; };
  } ''
    install -Dm0644 "$policy" "$out/share/dbus-1/system.d/${busName}.conf"
  '';

  polkitActions = pkgs.runCommand "fractal-trigger-polkit-actions" { } ''
    install -Dm0644 ${./polkit.policy} \
      "$out/share/polkit-1/actions/${busName}.policy"
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

    mode = lib.mkOption {
      type = lib.types.enum [ "standalone" "enrolled" ];
      default = "standalone";
      description = ''
        Authorization mode. `standalone` (consumer) authorizes callers via
        polkit; `enrolled` (enterprise) authorizes switches via an offline
        signature + nonce.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    services.dbus.packages = [ dbusPolicy ];

    security.polkit.enable = true;
    environment.systemPackages = [ polkitActions ];

    # v1: grant the agent the trigger actions non-interactively. Interactive
    # auth (consumer desktop) and enrolled signatures replace this later.
    security.polkit.extraConfig = ''
      polkit.addRule(function(action, subject) {
        if ((action.id == "systems.staticroot.trigger.switch" ||
             action.id == "systems.staticroot.trigger.lock") &&
            subject.user == "${cfg.agentUser}") {
          return polkit.Result.YES;
        }
      });
    '';

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
        Environment = "FRACTAL_TRIGGER_MODE=${cfg.mode}";
      };
    };
  };
}
