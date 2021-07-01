# Volatility3 Autoruns plugin
Port of tomchop's autoruns plugin for Volatility 3

This plugin has been tested using tomchop's own test_data image and does match the expected output.

## How-to

Drop the autorun.py file in the ```plugins/windows``` directory of volatility 3. Volatility should automatically detect it, then call it by typing ```windows.autorun.Autoruns```

Here are the available options for this plugin:

```--verbose``` Shows extra information that would normally be filtered (like Services from the System32 folder)

```--asep=autoruns services appinit winlogon tasks activesetup``` - Use it to focus on specific ASEPS. Options are: autoruns (Run, RunOnce, etc.), services, appinit, winlogon, tasks, and activesetup. You can specify any combination of them with a space-separated list: autoruns services. Leave blank to get all ASEPs.

## Special thanks

Special thanks to tomchop for making the plugin available for the community.
