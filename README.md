# HAP Tool

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

The HAP program is a versatile tool designed to facilitate the enumeration of Windows hosts, Active Directory, and Linux hosts, and seamlessly send the collected data to an Elastic database. This project aims to provide a convenient and efficient solution for gathering comprehensive information about various systems within a network, aiding system administrators, and security professionals in monitoring and analyzing the network.

## Features

- **Windows Host Enumeration:** The tool leverages various techniques and Windows APIs to retrieve detailed information about Windows hosts, including system configuration, hardware details, installed software, and network settings.

- **Active Directory Enumeration:** HAP tool enumerates essential entities of Active Directory, including users, groups, and computer objects, capturing vital information about network entities and their relationships.

- **Linux Host Enumeration:** The tool efficiently enumerates Linux hosts, collecting a range of information including user accounts, running processes, and network connections, providing detailed insights into the configuration and operational status of Linux machines in the network.

- **Elastic Database Integration:** HAP ensures that after the enumeration process is complete, the tool securely transmits the collected data to an Elastic database, enabling centralized storage, analysis, and visualization of the gathered information.

- **Automation and Scalability:** With scripting and automation capabilities, HAP can be easily incorporated into existing workflows or integrated with other security or monitoring systems. It is scalable and adept at handling large-scale enumeration tasks across diverse network infrastructures.

- **Configurable and Extensible:** Offering various configuration options, the tool allows customization of the data collection process as per specific requirements. Its extensibility through plugins enables the addition of new data collection modules or integration with other systems.

## Getting Started

To get started with the HAP tool, please follow the instructions in the [Installation Guide](docs/installation.md). The guide provides step-by-step instructions for setting up the tool and configuring the Elastic database integration. 

For detailed usage instructions and examples, refer to the [User Manual](docs/user-manual.md). It covers the various features, command-line options, and advanced usage scenarios of the HAP tool.

## Contributing

We welcome contributions! If you have suggestions, feature requests, or bug reports, please open an issue or submit a pull request. For more details, please read our [Contribution Guidelines](CONTRIBUTING.md).

## License

This project is licensed under the [MIT License](LICENSE).
