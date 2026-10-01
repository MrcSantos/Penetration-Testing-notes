In order to create a python2 virtualenv in 2026 one could do this: 
```
sudo apt install python2
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py
pip2 install --user pipenv
pipenv --python 2.7
```

To install dependencies:
```
cd project_folder
pipenv install requests
```

To run commands:
```
pipenv run python main.py
```
