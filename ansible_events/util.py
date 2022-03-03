import jinja2
import yaml
import os
import json
import multiprocessing as mp

from typing import Dict, Union

from typing import Any

def get_horizontal_rule(character):
    try:
        return character * int(os.get_terminal_size()[0])
    except OSError:
        return character * 80


def render_string(value: str, context: Dict) -> str:
    return jinja2.Template(value, undefined=jinja2.StrictUndefined).render(context)


def render_string_or_return_value(value: Any, context: Dict) -> Any:
    if isinstance(value, str):
        if value.startswith('{{') and value.endswith('}}'):
            return context[value[2:-2]]
        else:
            return render_string(value, context)


def substitute_variables(value: Union[str, int, Dict], context: Dict) -> Union[str, int, Dict]:
    if isinstance(value, str):
        return render_string_or_return_value(value, context)
    elif isinstance(value, dict):
        new_value = value.copy()
        for key, subvalue in new_value.items():
            new_value[key] = render_string_or_return_value(subvalue, context)
        return new_value
    else:
        return value


def load_inventory(inventory_file: str) -> Any:

    with open(inventory_file) as f:
        inventory_data = yaml.safe_load(f.read())
    return inventory_data