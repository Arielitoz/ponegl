@echo off

cd /
gpupdate /force
c: 
cd /Users/%username%/Desktop
msg * "Bem-vindo(a) %username% ao sistema AJMR Motors!"

IF EXIST PastaPessoal-%username% (
    xcopy PastaPessoal-%username% PastaPessoal-%username%-bkp /E /H /C /I
) ELSE (
    mkdir PastaPessoal-%username%
)
start https://www.fatec.saocaetano.edu.br/