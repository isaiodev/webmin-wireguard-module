# Changelog

All notable changes to the Webmin WireGuard Module will be documented in this file.

## [Unreleased] - 2024-12-20

### Fixed
- **Fixed undefined subroutine errors**: Added missing `has_command_in_path` function with fallback implementation for PATH searching
- **Fixed ui_text error**: Replaced non-existent `ui_text` function with simple HTML print statement
- **Fixed ui_table_header error**: Replaced non-existent `ui_table_header` function with HTML table header row
- **Added missing functions**: 
  - `can_edit()` - Checks user write permissions based on Webmin ACL
  - `get_config_path()` - Returns full path to WireGuard interface configuration files

### Added
- **Custom config directory support**: Added configuration form in main interface to specify custom WireGuard config directory
- **Flexible backend detection**: Updated backend detection to prioritize any existing config directory for both host and Docker modes
- **Installation script**: Created `install_module.sh` script for proper module installation with automatic path detection
- **Docker container actions**: Added proper support for linuxserver/wireguard containers with `docker exec` commands
- **Container status display**: Backend detection now shows container running status

### Changed
- **Backend detection logic**: Modified to use configured directory path for both host and Docker backends instead of separate docker_config_dir
- **Module installation process**: Improved installation script to properly stop/start Webmin and clear module cache
- **Docker actions**: Implemented `wg-quick up/down` commands via `docker exec` for linuxserver/wireguard containers
- **Container detection**: Enhanced to specifically detect linuxserver/wireguard containers

### Technical Details
- Fixed Perl execution errors that prevented module from loading in Webmin
- Improved compatibility across different Webmin versions by implementing fallback functions
- Enhanced configuration flexibility for non-standard WireGuard setups