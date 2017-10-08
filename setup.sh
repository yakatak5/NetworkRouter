udo apt-get update;
sudo apt-get install -y python-dev vim-nox python-setuptools flex bison traceroute;
cd ~;
git clone git clone git://github.com/dound/ltprotocol.git;
cd ltprotocol;
sudo python setup.py install;
cd ~/pox;
git checkout f95dd1a81584d716823bbf565fa68254416af603;
cd ~;
git clone https://agember@bitbucket.org/agember/cs640_project2.git;

