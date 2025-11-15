#!/bin/bash

# F0RT1KA Security Test Browser - Startup Script

echo "======================================================"
echo "  F0RT1KA SECURITY TEST BROWSER"
echo "======================================================"
echo ""

# Check if backend dependencies are installed
if [ ! -d "backend/node_modules" ]; then
    echo "Installing backend dependencies..."
    cd backend && npm install && cd ..
fi

# Check if frontend dependencies are installed
if [ ! -d "frontend/node_modules" ]; then
    echo "Installing frontend dependencies..."
    cd frontend && npm install && cd ..
fi

echo ""
echo "Starting servers..."
echo ""
echo "Backend API will run on: http://localhost:3001"
echo "Frontend app will run on: http://localhost:5173"
echo ""
echo "Press Ctrl+C in each terminal to stop the servers"
echo ""
echo "======================================================"
echo ""

# Open two terminal windows
echo "Opening backend server..."
gnome-terminal -- bash -c "cd backend && npm run dev; exec bash" 2>/dev/null || \
xterm -e "cd backend && npm run dev; exec bash" 2>/dev/null || \
echo "Please open a terminal and run: cd backend && npm run dev"

sleep 2

echo "Opening frontend server..."
gnome-terminal -- bash -c "cd frontend && npm run dev; exec bash" 2>/dev/null || \
xterm -e "cd frontend && npm run dev; exec bash" 2>/dev/null || \
echo "Please open a terminal and run: cd frontend && npm run dev"

echo ""
echo "Servers starting..."
echo "Once both servers are running, open http://localhost:5173 in your browser"
echo ""
