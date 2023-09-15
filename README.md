# gve_devnet_fips_compliant_checklist_audit
prototype code that will query a list of devices connected to DNA Center and audit the show running configuration for each device. The audit will search for Non-Approved algorithms in the Non-FIPS mode services and create a report on the audit status

![/IMAGES/non-approve_algs.png](/IMAGES/non-approve_algs.png)


## Contacts
* Jorge Banegas & Rey Diaz

## Solution Components
* DNAC
* Python 3

## Prerequisites
**DNA Center Credentials**: In order to use the DNA Center APIs, you need to make note of the IP address, username, and password of your instance of DNA Center. Note these values to add to the credentials file during the installation phase.

## Installation/Configuration
1. Clone this repository with `git clone [repository name]`
2. Add the IP address, username, and password that you collected in the Prerequisites section to the config file
```
ip: ip or url of DNAC
username: username of DNAC
password: password of DNAC
```
3. Set up a Python virtual environment. Make sure Python 3 is installed in your environment, and if not, you may download Python [here](https://www.python.org/downloads/). Once Python 3 is installed in your environment, you can activate the virtual environment with the instructions found [here](https://docs.python.org/3/tutorial/venv.html).
4. Install the requirements with `pip3 install -r requirements.txt`

## Usage
Edit the config.py to include the list of devices in which you want to review the configuration
```
device_list = ['x.x.x.x','x.x.x.x']
```
To run the code, use the command:
```
$ python3 main.py
```

# Screenshots
![/IMAGES/0image.png](/IMAGES/example_output.png)

![/IMAGES/0image.png](/IMAGES/0image.png)

### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.