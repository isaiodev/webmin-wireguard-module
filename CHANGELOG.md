# Changelog

All notable changes to the Webmin WireGuard Module will be documented in this file.

## [Unreleased] - 2024-12-20

### Fixed
- **Fixed undefined subroutine errors**: Added missing `has_command_in_path` function with fallback implementation for PATH searching
- **Fixed ui_text error**: Replaced non-existent `ui_text` function with simple HTML print statement
- **Fixed ui_table_header error**: Replaced non-existent `ui_table_header` function with HTML table header row
- **Fixed backend detection**: Corrected logic to properly detect Docker mode when custom config directory is specified
- **Fixed missing action buttons**: Added missing `urlize` function and fixed backend detection for Docker containers
- **Fixed action button visibility**: Modified can_edit function to be more permissive and always show action buttons
- **Fixed missing library functions**: Completed all missing functions (save_config_lines, suggest_next_ip, get_peer_stats, apply_changes, service_action)
- **Fixed peers.cgi for Docker**: Updated to work with Docker containers using parse_wg_config_docker
- **Added missing functions**: 
  - `can_edit()` - Checks user write permissions based on Webmin ACL
  - `get_config_path()` - Returns full path to WireGuard interface configuration files
  - `urlize()` - URL encodes interface names for links

### Added
- **Custom config directory support**: Added configuration form in main interface to specify custom WireGuard config directory
- **Flexible backend detection**: Updated backend detection to prioritize any existing config directory for both host and Docker modes
- **Installation script**: Created `install_module.sh` script for proper module installation with automatic path detection
- **Docker container actions**: Added proper support for linuxserver/wireguard containers with `docker exec` commands
- **Container status display**: Backend detection now shows container running status
- **Docker container config reading**: Added ability to read config files from inside Docker containers when host-mounted directory is not accessible
- **Docker container name configuration**: Added form field to specify Docker container name (e.g., 'wireguard')
- **Backend type selection**: Added radio buttons to explicitly choose between Docker Container and Native Linux Installation
- **Configurable container config path**: Added field to specify where WireGuard config files are located inside the Docker container
- **QR code generation**: Added QR code modal display for new peer configurations
- **Auto-install qrencode**: Install script now automatically detects and installs qrencode package
- **Add new devices/peers**: Full functionality to add new WireGuard peers with client config generation

### Changed
- **Backend detection logic**: Modified to use configured directory path for both host and Docker backends instead of separate docker_config_dir
- **Module installation process**: Improved installation script to properly stop/start Webmin and clear module cache
- **Docker actions**: Implemented `wg-quick up/down` commands via `docker exec` for linuxserver/wireguard containers
- **Container detection**: Enhanced to specifically detect linuxserver/wireguard containers
- **Docker config file detection**: Now prioritizes reading config files from inside Docker container (`/config`) over host-mounted directories
- **Backend selection**: Replaced auto-detection with explicit user choice via radio buttons for clearer configuration

### Technical Details
- Fixed Perl execution errors that prevented module from loading in Webmin
- Improved compatibility across different Webmin versions by implementing fallback functions
- Enhanced configuration flexibility for non-standard WireGuard setups