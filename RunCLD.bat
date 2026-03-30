@echo off
title CLD T1 Policy
powershell -ExecutionPolicy Bypass -NoExit -File "%~dp0CLD_T1_Policy.ps1"
