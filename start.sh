#!/bin/bash

# RSA Encrypted Chat Application - Quick Start Script

echo "🚀 RSA Encrypted Chat Application - Quick Start"
echo "=================================================="

# Check if we're in the right directory
if [ ! -f "manage.py" ]; then
    echo "❌ Error: manage.py not found. Are you in the project directory?"
    exit 1
fi

# Activate virtual environment
echo "📦 Activating virtual environment..."
source .venv/bin/activate

# Check dependencies
echo "🔍 Checking dependencies..."
python -c "import django; import rest_framework; import corsheaders; import cryptography" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "⚠️  Installing missing dependencies..."
    pip install Django djangorestframework django-cors-headers cryptography python-decouple pillow
fi

# Run migrations (if needed)
echo "📊 Running database migrations..."
python manage.py migrate --noinput

# Collect static files
# echo "📁 Collecting static files..."
# python manage.py collectstatic --noinput

echo ""
echo "✅ Setup complete!"
echo ""
echo "🎯 Starting development server..."
echo "=================================================="
echo ""
echo "📱 Open your browser and go to:"
echo "   http://localhost:8000/"
echo ""
echo "📚 Documentation:"
echo "   - README.md - Project overview"
echo "   - GUIDE.md - Detailed guide"
echo "   - API Reference in README.md"
echo ""
echo "🔐 First time?"
echo "   1. Click 'Register' to create an account"
echo "   2. Create 2+ accounts to test messaging"
echo "   3. Create a chat and exchange encrypted messages"
echo ""
echo "Press Ctrl+C to stop the server"
echo "=================================================="
echo ""

# Start the development server
python manage.py runserver
