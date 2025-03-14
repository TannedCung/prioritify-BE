# Prioritify - Daily Planner Application

Prioritify is a daily planner application designed to help users manage their tasks and events efficiently. This project is built using Django, a powerful web framework for Python.

## Features

- User authentication and registration
- Task management
- Event scheduling
- Dashboard for an overview of tasks and events

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd prioritify
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

4. Apply migrations:
   ```
   python manage.py migrate
   ```

5. Create a superuser (optional):
   ```
   python manage.py createsuperuser
   ```

6. Run the development server:
   ```
   python manage.py runserver
   ```

## Usage

- Access the application at `http://127.0.0.1:8000/`
- Use the admin panel at `http://127.0.0.1:8000/admin` to manage tasks and users.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or features.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.