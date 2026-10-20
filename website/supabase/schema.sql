-- NigraniAI Demo Booking Schema
-- Run this in your Supabase SQL Editor

-- Create the demo_bookings table
CREATE TABLE demo_bookings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  booking_reference TEXT UNIQUE NOT NULL,
  full_name TEXT NOT NULL,
  business_email TEXT NOT NULL,
  phone_number TEXT NOT NULL,
  organization_name TEXT NOT NULL,
  designation TEXT NOT NULL,
  industry TEXT NOT NULL,
  organization_size TEXT NOT NULL,
  preferred_date DATE NOT NULL,
  preferred_time TEXT NOT NULL,
  areas_of_interest TEXT[] NOT NULL DEFAULT '{}',
  additional_requirements TEXT,
  status TEXT NOT NULL DEFAULT 'PENDING',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE demo_bookings ENABLE ROW LEVEL SECURITY;

-- Create policy: Allow anonymous users to INSERT valid demo requests
-- We use a CHECK constraint to ensure only valid data is inserted
CREATE POLICY "Allow anonymous demo booking inserts" ON demo_bookings
  FOR INSERT
  TO anon
  WITH CHECK (
    -- Basic validation at database level
    full_name IS NOT NULL AND
    business_email IS NOT NULL AND
    phone_number IS NOT NULL AND
    organization_name IS NOT NULL AND
    designation IS NOT NULL AND
    industry IS NOT NULL AND
    organization_size IS NOT NULL AND
    preferred_date IS NOT NULL AND
    preferred_time IS NOT NULL
  );

-- Prevent anonymous users from SELECT, UPDATE, DELETE
-- (No policies created for these operations means they are denied by default with RLS enabled)

-- Create an index for faster lookups by booking reference
CREATE INDEX idx_demo_bookings_booking_reference ON demo_bookings(booking_reference);

-- Create an index for querying by status and date
CREATE INDEX idx_demo_bookings_status_created ON demo_bookings(status, created_at DESC);

-- Optional: Function to generate booking reference
CREATE OR REPLACE FUNCTION generate_booking_reference()
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
  ref TEXT;
BEGIN
  ref := 'NIG-' || TO_CHAR(NOW(), 'YYYYMMDD') || '-' || UPPER(SUBSTRING(MD5(RANDOM()::TEXT) FROM 1 FOR 6));
  RETURN ref;
END;
$$;