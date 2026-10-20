import { createClient, SupabaseClient } from '@supabase/supabase-js'

// Support both VITE_ and NEXT_PUBLIC_ prefixes for flexibility
const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || import.meta.env.NEXT_PUBLIC_SUPABASE_URL
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || import.meta.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

let supabase: SupabaseClient | null = null

if (supabaseUrl && supabaseAnonKey) {
  supabase = createClient(supabaseUrl, supabaseAnonKey)
} else {
  console.warn('Supabase environment variables not configured. Demo booking will not work.')
}

export { supabase }

export type DemoBookingData = {
  full_name: string
  business_email: string
  phone_number: string
  organization_name: string
  designation: string
  industry: string
  organization_size: string
  preferred_date: string
  preferred_time: string
  areas_of_interest: string[]
  additional_requirements?: string
}

export async function submitDemoBooking(data: DemoBookingData): Promise<{ success: boolean; bookingReference?: string; error?: string }> {
  if (!supabase) {
    return { success: false, error: 'Demo booking is not configured. Please add Supabase credentials to .env.local and restart the dev server.' }
  }

  // Generate booking reference
  const bookingReference = `NIG-${new Date().toISOString().slice(0, 10).replace(/-/g, '')}-${Math.random().toString(36).substring(2, 8).toUpperCase()}`

  const { error } = await supabase
    .from('demo_bookings')
    .insert({
      booking_reference: bookingReference,
      full_name: data.full_name,
      business_email: data.business_email,
      phone_number: data.phone_number,
      organization_name: data.organization_name,
      designation: data.designation,
      industry: data.industry,
      organization_size: data.organization_size,
      preferred_date: data.preferred_date,
      preferred_time: data.preferred_time,
      areas_of_interest: data.areas_of_interest,
      additional_requirements: data.additional_requirements || null,
      status: 'PENDING',
    })

  if (error) {
    console.error('Demo booking submission error:', error)
    // Return a user-friendly error without exposing sensitive details
    return { success: false, error: 'Unable to submit your request. Please try again later.' }
  }

  return { success: true, bookingReference }
}