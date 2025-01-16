#!/bin/bash
curl -f http://localhost:5000/api/health || exit 1
