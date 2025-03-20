from flask import render_template

def get_tool_info():
    return {'name': 'Shortener', 'description': 'Shorten URLs.', 'route': '/tools/shortener'}

def register_routes(app):
    @app.route('/tools/shortener')
    def shortener():
        return render_template('base.html', content='<h1>Shortener</h1><p>Coming soon!</p>')