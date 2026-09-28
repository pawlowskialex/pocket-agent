# nix-darwin module: runs the daemon as a launchd user agent.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.pocket-agent;
  settingsFormat = pkgs.formats.json { };
  configFile = settingsFormat.generate "pocket-agent.json" cfg.settings;
  home = config.users.users.${cfg.user}.home;
  logFile = "${home}/Library/Logs/pocket-agent.log";
in
{
  options.services.pocket-agent = {
    enable = lib.mkEnableOption "pocket-agent, an SSH agent that keeps the private keys on your phone";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "pocket-agent.packages.\${system}.default";
      description = "The pocket-agent package to run.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = config.system.primaryUser;
      defaultText = lib.literalExpression "config.system.primaryUser";
      description = "User the agent runs for. Used for the home directory and log path.";
    };

    settings = lib.mkOption {
      type = settingsFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          allowed_nodes = [ "iphone" ];
          sign_timeout_seconds = 120;
        }
      '';
      description = ''
        Contents of the daemon's JSON config. Anything left out takes the built-in default;
        `allowed_logins` and `public_url` are derived from `tailscale status` at start when
        unset, and the Tailscale HTTPS certificate is fetched automatically. See the README
        for every key.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];

    # Lets `pocket-agent status` / `test-notify` in a shell find the same config the daemon uses.
    environment.variables.POCKET_AGENT_CONFIG = toString configFile;

    launchd.user.agents."pocket-agent" = {
      command = "${lib.getExe cfg.package} --config ${configFile} serve";
      serviceConfig = {
        KeepAlive = true;
        RunAtLoad = true;
        ProcessType = "Interactive";
        StandardOutPath = logFile;
        StandardErrorPath = logFile;
        # The tailscale CLI must be reachable; launchd agents get a minimal PATH.
        EnvironmentVariables.PATH = lib.concatStringsSep ":" [
          "/usr/local/bin"
          "/Applications/Tailscale.app/Contents/MacOS"
          "/run/current-system/sw/bin"
          "/usr/bin"
          "/bin"
        ];
      };
    };
  };
}
