from flask import redirect, url_for, session, jsonify
import requests
from utils.decorators import login_required

def register_routes(app):
    @app.route('/')
    @login_required
    def index():
        if session.get('is_admin'):
            return redirect(url_for('users.dashboard'))
        return redirect(url_for('connections.view_connections'))

    @app.route('/test-api-connection')
    def test_api_connection():
        try:
            app.logger.info(f"Testing connection to API at {app.config['API_URL']}")
            response = requests.get(f'{app.config["API_URL"]}/api/health')
            app.logger.info(f"API Response: Status={response.status_code}, Content={response.text}")
            return jsonify({
                'api_url': app.config['API_URL'],
                'status_code': response.status_code,
                'response': response.text
            })
        except Exception as e:
            app.logger.error(f"Error connecting to API: {str(e)}")
            return jsonify({
                'error': str(e),
                'api_url': app.config['API_URL']
            }), 500
