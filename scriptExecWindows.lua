# Filename:    4_CreateUser_CP.ps1
# Description: Creates a user in Active Directory.  This is part of
#              the Azure AD Connect password hash sync tutorial.
#
# DISCLAIMER:
# Copyright (c) Microsoft Corporation. All rights reserved. This 
# script is made available to you without any express, implied or 
# statutory warranty, not even the implied warranty of 
# merchantability or fitness for a particular purpose, or the 
# warranty of title or non-infringement. The entire risk of the 
# use or the results from the use of this script remains with you.
#
#
#
 = [Anna, ariel, matheu]
#
#Declare variables
#GivenName Primeiro Nome
$Givenname = "João", "Maria", "Pedro", "Ana", "Paulo", "Carla", "Marcos", "Aline", "Lucas", "Fernanda", "Rafael", "Juliana", "Bruno", "Camila", "Eduardo", "Beatriz", "Rodrigo", "Tatiana", "Gustavo", "Patricia"
#Surname Sobrenome
$Surname = "Silva", "Oliveira", "Costa" , "Souza", "Pereira", "Santos", "Rodrigues", "Almeida", "Lima", "Gomes", "Barbosa", "Teixeira", "Fernandes", "Martins", "Araujo", "Ribeiro", "Carvalho", "Moreira", "Cardoso", "Mendes"
#Nome Completo
$Displayname = "João Silva", "Maria Oliveira", "Pedro Costa", "Ana Souza", "Paulo Pereira", "Carla Santos", "Marcos Rodrigues", "Aline Almeida", "Lucas Lima", "Fernanda Gomes", "Rafael Barbosa", "Juliana Teixeira", "Bruno Fernandes", "Camila Martins", "Eduardo Araujo", "Beatriz Ribeiro", "Rodrigo Carvalho", "Tatiana Moreira", "Gustavo Cardoso", " Patrícia Mendes"
#Nome completo
$Name = "João Silva", "Maria Oliveira", "Pedro Costa", "Ana Souza", "Paulo Pereira", "Carla Santos", "Marcos Rodrigues", "Aline Almeida", "Lucas Lima", "Fernanda Gomes", "Rafael Barbosa", "Juliana Teixeira", "Bruno Fernandes", "Camila Martins", "Eduardo Araujo", "Beatriz Ribeiro", "Rodrigo Carvalho", "Tatiana Moreira", "Gustavo Cardoso", " Patrícia Mendes"
#UserPrincipalName -upn
$upname = "joao.silva", "maria.oliveira", "pedro.costa", "ana.souza", "paulo.pereira", "carla.santos", "marcos.rodrigues", "aline.almeida", "lucas.lima", " fernanda.gomes", "rafael.barbosa", "juliana.teixeira", "bruno.fernandes", "camila.martins", "eduardo.araujo", "beatriz.ribeiro", "rodrigo.carvalho", "tatiana.moreira", "gustavo.cardoso", "patricia.mendes"
#SamAccountName
$samAcc = "joao.silva", "maria.oliveira", "pedro.costa", "ana.souza", "paulo.pereira", "carla.santos", "marcos.rodrigues", "aline.almeida", "lucas.lima", " fernanda.gomes", "rafael.barbosa", "juliana.teixeira", "bruno.fernandes", "camila.martins", "eduardo.araujo", "beatriz.ribeiro", "rodrigo.carvalho", "tatiana.moreira", "gustavo.cardoso", "patricia.mendes"
$Password = "SenhaForte123!", "SenhaForte456!", "SenhaForte789!", "SenhaForte101!", "SenhaForte202!", "SenhaForte303!", "SenhaForte404!", "SenhaForte505!", "SenhaForte606!", "SenhaForte707!", "SenhaForte808!", "SenhaForte909!", "SenhaForte111!", "SenhaForte222!", "SenhaForte333!", "SenhaForte444!", "SenhaForte555!", "SenhaForte666!", "SenhaForte777!", "SenhaForte888!"

#Create the user
New-ADUser -Name $Name -GivenName $Givenname -Surname $Surname -DisplayName $Displayname -AccountPassword $SecureString

#Set the password to never expire
Set-ADUser -Identity $Identity -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Enabled $true

Dados de usuário - primeiroNome;ultimoNome;Iniciais;nomeCompleto;usuarioLogonName;senha;confirmaçãoSenha;


Comando para criar usuários:

New-ADUser -Name "Jason bone" -GivenName "Jason" -Surname "Boue" -UserPrincipalName "juse.burne" -SamAccountName
 "Jon.Bourne" -AccountPassword (ConvertTo-SecureString -AsPlainText "323212Rel" -Force) -DisplayName "Jason Bourne" -Ena
bled $True

New-ADUser -Name $Name -GivenName $GivenName -Surname $Surname -UserPrincipalName $upname -SamAccountName
 $samAcc -AccountPassword (ConvertTo-SecureString -AsPlainText $password -Force) -DisplayName $Displayname -Ena
bled $True