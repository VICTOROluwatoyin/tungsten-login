from flask import render_template

def get_tool_info():
    return {'name': 'Scraper', 'description': 'Scrape websites.', 'route': '/tools/scraper'}

def register_routes(app):
    @app.route('/tools/scraper')
    def scraper():
        return render_template('base.html', content='<h1>Scraper</h1><p>Coming soon!</p>')