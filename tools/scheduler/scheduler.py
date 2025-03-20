from flask import render_template

def get_tool_info():
    return {'name': 'Scheduler', 'description': 'Schedule meetings.', 'route': '/tools/scheduler'}

def register_routes(app):
    @app.route('/tools/scheduler')
    def scheduler():
        return render_template('base.html', content='<h1>Scheduler</h1><p>Coming soon!</p>')