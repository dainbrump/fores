<div align="center" id="top"> 
  <img src="./.github/fores-logo.png" alt="Fores" />
</div>

<h1 align="center">Fores</h1>

<p align="center">
  <img alt="Github top language" src="https://img.shields.io/github/languages/top/dainbrump/fores?color=56BEB8">
  <img alt="Github language count" src="https://img.shields.io/github/languages/count/dainbrump/fores?color=56BEB8">
  <img alt="Repository size" src="https://img.shields.io/github/repo-size/dainbrump/fores?color=56BEB8">
  <img alt="License" src="https://img.shields.io/github/license/dainbrump/fores?color=56BEB8">
  <img alt="Github issues" src="https://img.shields.io/github/issues/dainbrump/fores?color=56BEB8" />
  <img alt="Github forks" src="https://img.shields.io/github/forks/dainbrump/fores?color=56BEB8" />
  <img alt="Github stars" src="https://img.shields.io/github/stars/dainbrump/fores?color=56BEB8" />
</p>

<h4 align="center">🚧 Fores is still a work in progress 🚧</h4>

<hr>

<p align="center">
  <a href="#about">About</a> &#xa0; | &#xa0; 
  <a href="#features">Features</a> &#xa0; | &#xa0;
  <a href="#technologies">Technologies</a> &#xa0; | &#xa0;
  <a href="#license">License</a> &#xa0; | &#xa0;
  <a href="https://github.com/dainbrump" target="_blank">Author</a>
</p>

<br>

## About

`Fores` is a Rust library designed to parse SSH client configuration files (typically `~/.ssh/config`) into a structured, programmatic representation. It handles the complexities of the SSH config format, including `Include` directives, and provides a robust data structure that you can use to analyze, modify, and generate valid SSH configurations.

The name "Fores" is derived from the Latin word for "door" or "double door," reflecting the library's role in managing access configurations to remote systems through SSH. Just as a door provides a controlled entry point, `Fores` provides a structured way to interact with the configuration that governs SSH connections. It is a counterpart to the `Cardea` crate, named after the Roman goddess of the hinge, which handles parsing of SSHD (server) configuration files. Together, `Fores` and `Cardea` provide a comprehensive solution for managing SSH configurations in Rust applications.

The primary goal of `Fores` is to simplify working with SSH client configurations. By parsing the configuration file into a well-defined data structure, `Fores` allows you to:

- Programmatically access configuration options for different hosts.
- Validate configurations for correctness and consistency.
- Modify existing configurations or create new ones from scratch.
- Generate valid SSH config files from the structured data.

### Example Use Cases

`Fores` can be used in a variety of applications that interact with SSH configurations. Some potential use cases include:

- **GUI SSH Client**: `Fores` can be integrated into a desktop application to provide a user-friendly interface for managing SSH configurations. Users could visually explore their configuration, add or modify hosts and options, and validate the changes before applying them.
- **Configuration Management Tools**: `Fores` can be used to build tools that automatically manage SSH configurations across multiple systems. For example, you could create a tool that enforces certain security policies or synchronizes configurations across a fleet of machines.
- **Automated Testing**: `Fores` can be used to create test suites for SSH client configurations. You could define a set of rules and use Fores to automatically check if configurations comply with those rules.
- **SSH Config Generators**: `Fores` can form the foundation of tools that generate SSH configuration files from other data sources, such as databases or YAML files.
- **Security Analysis**: `Fores` can be used to build security analysis tools that scan SSH configurations for potential vulnerabilities or misconfigurations.

`Fores` provides a robust and efficient way to work with SSH client configurations in your Rust projects. Its comprehensive parsing capabilities, structured data representation, and flexible API make it a valuable tool for a wide range of applications.

## Features

:heavy_check_mark: Data structure handles full SSH spec configuration directives.

:heavy_check_mark: Tree-structured results accurately represents the complete structure of the configuration file and any files included via `Include` directives.

:heavy_check_mark: Graceful error handling - Designed to report configuration errors without crashing.

### Planned / Possible

- **Customizable output?** Allow the library consumer to define a "custom" tree-structure to return the output in.
- **Applicable Traits?** May be useful to implement the customizable output but might also be useful in other scenarios.
- **Command-line parsing?** Buildable to a simple command line utility for integration with / piping to shell programming.

## Technologies

The following tools were used in this project:

- [Rust](https://www.rust-lang.org/)

## License

This project is under license from MIT. For more details, see the [LICENSE](LICENSE.md) file.

Made with :heart: by <a href="https://github.com/dainbrump" target="_blank">Mark Litchfield</a>

<a href="#top">Back to top</a>
