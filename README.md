# Implementing a PWOSPF based Control Plane using P4Runtime

## Step 1: Create environment

Build virtual machine from this repo: https://github.com/p4lang/tutorials.git (howto in readme).

## Step 2: Clone repo and install dependencies

The VM got most of dependencies but control plane code requires some additional software.

Get in `p4_pwospf/` directory and run
```bash
cd p4_pwospf/
sudo pip install -r requirements.txt
```
`sudo` is necessary cause p4 user doesn't have all permissions.

## Step 2: Build and run project

Execute:
```bash
make build
make run
```

Then open controller's terminal
```
xterm c1
```

And run control plane by executing
```bash
python ./control_plane.py
```
