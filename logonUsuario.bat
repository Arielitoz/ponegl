@echo off

cd /
gpupdate /force
cd /Users/%username%/Desktop
IF EXIST PastaPessoal-%username% (
    xcopy PastaPessoal-%username% PastaPessoal-%username%-bkp /E /H /C /I
) ELSE (
    mkdir PastaPessoal-%username%
)
start https://www.fatec.saocaetano.edu.br/