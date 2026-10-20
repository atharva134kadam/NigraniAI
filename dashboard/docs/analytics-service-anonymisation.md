# analytics-service: switch to anonymised data

**For:** ShopSmart backend developers · **Decided:** 19 Oct 2026 · **Law:** DPDP Act 2023 s.4(1)(b), s.6(1). Personal data may be used only for the purposes customers were told about.

## The problem

The compliance dashboard's Data map shows `analytics-service` reading personal data, but no declared purpose covers analytics. Over 30 days, from the database logs:

| Table | Accesses | Personal data in it |
|---|---|---|
| `payments` | 84 SELECT | customer id, payment / order / refund ids, failure reason |
| `customer_orders` | 60 SELECT | shipping name, phone, address, payment reference |
| `customers` | 12 SELECT | name, email, phone |
| `order_line_items` | 12 SELECT | linked to the order and so to the customer |

These reads serve `/analytics/overview`, `/analytics/trends` and `/analytics/top-products`. None of these reports needs to know who the customer is.

## The change

Give analytics-service **aggregated views with no personal columns**, and let it read only those views.

```sql
-- daily sales, no customer data
create view public.analytics_daily_sales as
select date_trunc('day', o.created_at) as day,
       count(*)                        as orders,
       count(distinct o.customer_id)   as customers,      -- a count, never the ids
       sum(o.total_amount)             as revenue
from public.customer_orders o
group by 1;

-- product performance
create view public.analytics_product_sales as
select li.product_id, date_trunc('day', o.created_at) as day,
       sum(li.quantity) as units, sum(li.quantity * li.unit_price) as revenue
from public.order_line_items li join public.customer_orders o on o.id = li.order_id
group by 1, 2;

-- payment outcomes
create view public.analytics_payment_outcomes as
select date_trunc('day', created_at) as day, status, count(*) as payments, sum(amount) as amount
from public.payments
group by 1, 2;
```

The column names match ShopSmart's current schema (checked 19 Oct 2026). Then:

1. Point the three analytics endpoints at these views instead of the base tables.
2. Remove analytics-service's read access to `customers`, `customer_orders`, `order_line_items` and `payments`. If it uses its own database role: `revoke select on … from analytics_role; grant select on public.analytics_daily_sales, public.analytics_product_sales, public.analytics_payment_outcomes to analytics_role;`
3. For small groups (say fewer than 5 customers in a day), suppress or merge the figures, so nobody can be singled out.

## How you'll know it's done

You don't need to report back. The Data map updates live from the database logs:

- analytics-service's lines move from the four personal tables to the `analytics_*` views, shown as grey "not personal data" lines;
- the critical gap "analytics-service uses personal data from 4 table(s) outside its purposes" closes by itself once the old reads drop out of the 30-day window. Health rises from 85 towards 100.

Until then, the gap stays open on purpose, as a record that the decision is made but not yet implemented.

## Also worth fixing: the log masker (low priority)

The log pipeline masks 13-digit millisecond timestamps as `[CARD]` (for example Eureka's `StatusChangeEvent [timestamp=[CARD] …]`). They aren't card numbers. The dashboard now ignores them, but the masker should require a Luhn-valid 15–16-digit number and skip values next to `timestamp`.
