# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# xknx 3.20.0 (MIT, github.com/XKNX/xknx), Home Assistant's KNX library,
# and xknxproject 3.10.0 (GPL-2.0-only, github.com/XKNX/xknxproject), used
# only as test peers: xknx as an independent client of the simulated
# gateway and reader of its keyrings, xknxproject as a reader of its
# project exports, with client.py (ours) driving them.
#
#   docker build -t sigma-knxsim-xknx:3.20.0 .

FROM python:3.12-slim
RUN pip install --no-cache-dir xknx==3.20.0 xknxproject==3.10.0
COPY client.py /client.py
ENTRYPOINT ["python3", "-u", "/client.py"]
