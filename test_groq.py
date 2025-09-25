from openai import OpenAI
import os
import dotenv

dotenv.load_dotenv()

code = '''
    -- Example of a recursive CTE to find depth in a hierarchy (PostgreSQL/SQL Server)
    WITH RECURSIVE EmployeeHierarchy AS (
        SELECT employee_id, manager_id, employee_name, 1 AS depth
        FROM Employees
        WHERE manager_id IS NULL -- Base case: top-level employees

        UNION ALL

        SELECT e.employee_id, e.manager_id, e.employee_name, eh.depth + 1
        FROM Employees e
        JOIN EmployeeHierarchy eh ON e.manager_id = eh.employee_id
    )
    SELECT * FROM EmployeeHierarchy;
'''

client = OpenAI(
    api_key=os.environ.get("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1",
)

response = client.responses.create(
    input=f"""
        You are an AI assistant. Summarize the given code in exactly 2 sentences.

        code:
        ```{code}```

        Instructions:
        1. Detect the programming language automatically.
        2. First sentence: briefly describe what the code is trying to do.
        3. Second sentence: explain the actual runtime behavior (successful output or the exact error and why).
        4. Output must strictly follow this format:

        Language: <Detected Language>
        Summary: <two-sentence summary>
        """,
    model="llama-3.1-8b-instant",
)
print(response.output_text)
