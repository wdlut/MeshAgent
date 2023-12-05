#!/bin/bash
echo "Compile meshagent for linux ARCHID=$ARCHID and copy it into the MeshCentral directory"

DEBUGVERSION=""
if [ "$1" = "debug" ]; then
  DEBUGVERSION="DEBUG=1"
else
  echo "Add debug to create a debug version"
fi
read -p "Enter..."

echo "Compiliing meshagent_x86 just to export the modules..."
make clean
make linux ARCHID=5 BUILDROOT=1 -j8
if [ $? != 0] ; then
  echo "Error compiling agent"
  exit 1
fi

echo "Export modules..."
./meshagent_x86 -export
echo "Copy modules to export folder..."
cd modules_expanded
find  -type f -name \*.js -exec cp ../modules/{} . \;
cd ..
echo "Import modified modules in ILibDuktape_Polyfills.c..."
./meshagent_x86 -exec "require('code-utils').shrink({modulesPath:'/home/weda/MeshAgent/modules_expanded',filePath:'/home/weda/MeshAgent/microscript/ILibDuktape_Polyfills.c'});process.exit();"


echo "Compiliing agent $maFile for the target..."
make clean
make linux ARCHID=$archId BUILDROOT=1 $DEBUGVERSION -j8

[ -e DEBUG_$maFile ] && mv DEBUG_$maFile $maFile
cp -f $maFile ../MeshCentral/agents/


#Copy compiled agent to test machine
ipTestMachine=weda@192.168.202.75
portTestMachine=49126
meshPahtTestMachine=/weda/template/mesh

#ssh -p $portTestMachine $ipTestMachine killall meshagent
#scp -P $portTestMachine $maFile ${ipTestMachine}:${meshPahtTestMachine}/meshagent