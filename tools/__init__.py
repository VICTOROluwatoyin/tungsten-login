from importlib import import_module
import os

def get_available_tools():
    tools = []
    tool_dir = os.path.dirname(__file__)
    for filename in os.listdir(tool_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            module_name = filename[:-3]
            module = import_module(f'tools.{module_name}')
            tools.append(module.get_tool_info())
    return tools

def register_all_tools(app):
    tool_dir = os.path.dirname(__file__)
    for filename in os.listdir(tool_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            module_name = filename[:-3]
            module = import_module(f'tools.{module_name}')
            module.register_routes(app)