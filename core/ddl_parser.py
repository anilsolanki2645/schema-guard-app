"""
DDL Simulator & safe database schema transition recipe generator.
Supports PostgreSQL/Standard SQL DDL simulation and generates expand-and-contract migration paths.
"""
import re


def simulate_ddl_on_schema(ddl_sql, schema_columns):
    """
    Simulates proposed DDL changes on a list of column dictionaries.
    
    Args:
        ddl_sql (str): Raw SQL query (e.g. ALTER TABLE orders DROP COLUMN cost;)
        schema_columns (list): List of column dicts from the data contract
        
    Returns:
        tuple: (modified_columns_list, action_details_dict)
    """
    # Normalize whitespace and strip trailing semicolons/quotes
    clean_sql = re.sub(r'\s+', ' ', ddl_sql.strip()).strip(';').strip("'").strip('"')
    lower_sql = clean_sql.lower()
    
    # Deep copy the schema columns list to prevent original array modification
    new_cols = [dict(col) for col in schema_columns]
    action = None
    
    # 1. RENAME COLUMN
    # Match: ALTER TABLE name RENAME COLUMN old TO new
    rename_match = re.search(r'alter\s+table\s+(\w+)\s+rename\s+column\s+(\w+)\s+to\s+(\w+)', lower_sql)
    if rename_match:
        table_name = rename_match.group(1)
        old_col = rename_match.group(2)
        new_col = rename_match.group(3)
        
        found_col = None
        for col in new_cols:
            if col["name"].lower() == old_col:
                found_col = col
                break
                
        if not found_col:
            raise ValueError(f"Column '{old_col}' not found in contract schema for table '{table_name}'.")
            
        found_col["name"] = new_col
        action = {
            "type": "rename_column",
            "table": table_name,
            "old_column": found_col["name"],  # Original casing
            "new_column": new_col,
            "column_details": found_col
        }
        return new_cols, action

    # 2. DROP COLUMN
    # Match: ALTER TABLE name DROP COLUMN col
    # Match: ALTER TABLE name DROP col
    drop_match = re.search(r'alter\s+table\s+(\w+)\s+drop\s+(?:column\s+)?(\w+)', lower_sql)
    if drop_match:
        table_name = drop_match.group(1)
        col_name = drop_match.group(2)
        
        found_col = None
        for col in new_cols:
            if col["name"].lower() == col_name:
                found_col = col
                break
                
        if not found_col:
            raise ValueError(f"Column '{col_name}' not found in contract schema for table '{table_name}'.")
            
        new_cols.remove(found_col)
        action = {
            "type": "drop_column",
            "table": table_name,
            "column": found_col["name"]
        }
        return new_cols, action

    # 3. ADD COLUMN
    # Match: ALTER TABLE name ADD COLUMN col type [not null/null]
    # Match: ALTER TABLE name ADD col type
    add_match = re.search(r'alter\s+table\s+(\w+)\s+add\s+(?:column\s+)?(\w+)\s+([\w\(\),\s\d]+)', lower_sql)
    if add_match:
        table_name = add_match.group(1)
        col_name = add_match.group(2)
        type_and_constraints = add_match.group(3).strip()
        
        # Check if already exists
        for col in new_cols:
            if col["name"].lower() == col_name:
                raise ValueError(f"Column '{col_name}' already exists in table '{table_name}'.")
                
        # Parse nullability
        nullable = True
        if 'not null' in type_and_constraints:
            nullable = False
            type_str = type_and_constraints.replace('not null', '').strip()
        else:
            type_str = type_and_constraints.replace('null', '').strip()
            
        new_col = {
            "name": col_name,
            "type": type_str,
            "nullable": nullable
        }
        new_cols.append(new_col)
        action = {
            "type": "add_column",
            "table": table_name,
            "column": col_name,
            "new_type": type_str,
            "nullable": nullable
        }
        return new_cols, action

    # 4. ALTER COLUMN TYPE
    # Match: ALTER TABLE name ALTER COLUMN col TYPE type
    # Match: ALTER TABLE name MODIFY COLUMN col type
    # Match: ALTER TABLE name MODIFY col type
    alter_match = re.search(r'alter\s+table\s+(\w+)\s+alter\s+(?:column\s+)?(\w+)\s+type\s+([\w\(\),\s\d]+)', lower_sql)
    if not alter_match:
        alter_match = re.search(r'alter\s+table\s+(\w+)\s+modify\s+(?:column\s+)?(\w+)\s+([\w\(\),\s\d]+)', lower_sql)
        
    if alter_match:
        table_name = alter_match.group(1)
        col_name = alter_match.group(2)
        type_and_constraints = alter_match.group(3).strip()
        
        found_col = None
        for col in new_cols:
            if col["name"].lower() == col_name:
                found_col = col
                break
                
        if not found_col:
            raise ValueError(f"Column '{col_name}' not found in contract schema for table '{table_name}'.")
            
        # Parse nullability if set
        nullable = found_col.get("nullable", True)
        if 'not null' in type_and_constraints:
            nullable = False
            type_str = type_and_constraints.replace('not null', '').strip()
        elif 'null' in type_and_constraints:
            nullable = True
            type_str = type_and_constraints.replace('null', '').strip()
        else:
            type_str = type_and_constraints.strip()
            
        old_type = found_col["type"]
        found_col["type"] = type_str
        found_col["nullable"] = nullable
        
        action = {
            "type": "alter_type",
            "table": table_name,
            "column": found_col["name"],
            "old_type": old_type,
            "new_type": type_str,
            "nullable": nullable
        }
        return new_cols, action

    raise ValueError(
        "Unsupported DDL query format. Please use standard ALTER TABLE ADD/DROP/RENAME/ALTER statements."
    )


def generate_safe_transition_recipe(action, original_column=None, table_type="standard"):
    """
    Generates a copy-pasteable safe schema migration script implementing the
    Expand-and-Contract database refactoring pattern. Supports Standard or SCD Type 2 tables.
    """
    a_type = action.get("type")
    table = action.get("table", "my_table")
    
    if table_type == "scd2":
        if a_type == "add_column":
            col = action.get("column")
            new_type = action.get("new_type")
            return f"""-- 🕒 SCD TYPE 2 SAFE ADD COLUMN (Expand Phase)
-- Adding a column to an SCD Type 2 dimension requires it to be nullable to preserve historical rows:
ALTER TABLE {table} ADD COLUMN {col} {new_type};

-- Note: Do NOT add a NOT NULL constraint on historical rows.
-- New records can have the field populated, but historical versions will remain NULL."""

        elif a_type == "drop_column":
            col = action.get("column")
            return f"""-- 🕒 SCD TYPE 2 HISTORY GUARD (Breaking Alert)
-- ⚠️ WARNING: DO NOT DROP the column '{col}' from the physical SCD table!
-- Running ALTER TABLE DROP COLUMN will destroy the historical dimension data for all past rows.
-- 
-- Safe approach:
-- Step 1: Keep '{col}' in the physical database table.
-- Step 2: Update the Schema Guard contract to mark '{col}' as deprecated.
-- Step 3: Remove references to '{col}' in downstream queries and BI tools."""

        elif a_type == "rename_column":
            old_col = action.get("old_column")
            new_col = action.get("new_column")
            col_details = action.get("column_details", {})
            col_type = col_details.get("type", "varchar(255)")
            return f"""-- 🕒 SCD TYPE 2 SAFE COLUMN RENAME (Expand Phase Only)
-- Renaming columns in SCD tables breaks history tracking unless handled as an expansion:

-- Step 1: Add the new column '{new_col}' as nullable to target table:
ALTER TABLE {table} ADD COLUMN {new_col} {col_type};

-- Step 2: Backfill history. Copy values for all active and historical versions:
UPDATE {table} SET {new_col} = {old_col};

-- Step 3: Align target ingestion scripts or triggers to write to the new column.
-- Step 4: Re-point active analytics. Keep the old column '{old_col}' intact for historical reporting/queries, but deprecated for active writes."""

        elif a_type == "alter_type":
            col = action.get("column")
            old_type = action.get("old_type")
            new_type = action.get("new_type")
            return f"""-- 🕒 SCD TYPE 2 COLUMN TYPE CAST (Expand-and-Contract)
-- Direct type casts from '{old_type}' to '{new_type}' lock tables and can corrupt historical rows.

-- Step 1: Add a temporary transition column of the new type:
ALTER TABLE {table} ADD COLUMN {col}_new_type {new_type};

-- Step 2: Backfill history and cast values dynamically:
UPDATE {table} SET {col}_new_type = CAST({col} AS {new_type});

-- Step 3: Align pipeline/ingestion scripts to write to the new column.
-- Step 4: Deprecate or drop old column only after validating history records match new casts."""

    # Standard / Relational table recipes
    if a_type == "add_column":
        col = action.get("column")
        new_type = action.get("new_type")
        nullable = action.get("nullable")
        
        if not nullable:
            return f"""-- 🟢 SAFE ADD COLUMN WITH NOT NULL (Expand phase)
-- Adding a NOT NULL column directly without a default breaks downstream writes.
-- Step 1: Add the column as nullable first to allow old app versions to write records:
ALTER TABLE {table} ADD COLUMN {col} {new_type};

-- Step 2: Set default value for existing records to backfill:
UPDATE {table} SET {col} = 'YOUR_DEFAULT_VALUE' WHERE {col} IS NULL;

-- Step 3: Enforce NOT NULL once all rows are filled and applications write the field:
ALTER TABLE {table} ALTER COLUMN {col} SET NOT NULL;"""
        else:
            return f"""-- 🟢 SAFE ADD COLUMN (Compatible)
-- Adding a nullable column is fully compatible.
ALTER TABLE {table} ADD COLUMN {col} {new_type};"""

    elif a_type == "drop_column":
        col = action.get("column")
        return f"""-- 🟡 SAFE DROP COLUMN (Expand-and-Contract Pattern)
-- Dropping '{col}' instantly breaks downstream data contracts and APIs.
-- Step 1: Mark column as deprecated in schema-guard contract design.
-- Do NOT execute DROP COLUMN yet. Keep the column active in database.

-- Step 2: Remove references to '{col}' in all downstream queries, apps, and BI tools.

-- Step 3: Run final cleanup DDL script once logs show zero read connections:
ALTER TABLE {table} DROP COLUMN {col};"""

    elif a_type == "rename_column":
        old_col = action.get("old_column")
        new_col = action.get("new_column")
        col_details = action.get("column_details", {})
        col_type = col_details.get("type", "varchar(255)")
        
        return f"""-- 🔴 SAFE RENAME COLUMN (Expand-and-Contract Pattern)
-- Renaming '{old_col}' to '{new_col}' instantly crashes downstream applications.
-- Follow this zero-downtime transition recipe:

-- Step 1: Expand. Add the new column '{new_col}' as nullable:
ALTER TABLE {table} ADD COLUMN {new_col} {col_type};

-- Step 2: Replicate. Backfill existing records:
UPDATE {table} SET {new_col} = {old_col};

-- Step 3: Create a synchronization trigger so that writes continue to mirror (Postgres Example):
CREATE OR REPLACE FUNCTION sync_{table}_{old_col}_to_{new_col}()
RETURNS TRIGGER AS $$
BEGIN
    NEW.{new_col} := NEW.{old_col};
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_sync_{table}_{old_col}
BEFORE INSERT OR UPDATE ON {table}
FOR EACH ROW EXECUTE FUNCTION sync_{table}_{old_col}_to_{new_col}();

-- Step 4: Re-point. Update downstream queries, ORM models, and charts to read '{new_col}'.

-- Step 5: Contract. Drop old column and sync triggers after migration phase completes:
-- DROP TRIGGER trigger_sync_{table}_{old_col} ON {table};
-- ALTER TABLE {table} DROP COLUMN {old_col};"""

    elif a_type == "alter_type":
        col = action.get("column")
        old_type = action.get("old_type")
        new_type = action.get("new_type")
        
        return f"""-- 🔴 SAFE COLUMN TYPE CAST (Expand-and-Contract Pattern)
-- Direct type casts from '{old_type}' to '{new_type}' lock tables and can crash clients.
-- Follow this zero-downtime transition recipe:

-- Step 1: Add a temporary transition column of the new type:
ALTER TABLE {table} ADD COLUMN {col}_new_type {new_type};

-- Step 2: Backfill and cast values dynamically:
UPDATE {table} SET {col}_new_type = CAST({col} AS {new_type});

-- Step 3: Deploy code changes to write to both columns or handle conversion.

-- Step 4: Rename and drop triggers:
-- ALTER TABLE {table} DROP COLUMN {col};
-- ALTER TABLE {table} RENAME COLUMN {col}_new_type TO {col};"""

    return "-- No transition recipe required for this DDL change."
